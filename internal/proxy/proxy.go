package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"
)

type Config struct {
	Certificate []byte
	Key         []byte
	Logger      *slog.Logger
	Cors        bool
	Dir         string
	Hosts       []string
}

type Proxy struct {
	logger      *slog.Logger
	dir         string
	hosts       []string
	cors        bool
	proxy       *goproxy.ProxyHttpServer
	downloading sync.Map
}

func New(c *Config) (*Proxy, error) {
	if err := configureCertificate(c.Certificate, c.Key); err != nil {
		return nil, fmt.Errorf("failed to set up CA: %w", err)
	}

	proxy := goproxy.NewProxyHttpServer()

	p := &Proxy{
		logger: c.Logger,
		dir:    c.Dir,
		hosts:  c.Hosts,
		cors:   c.Cors,
		proxy:  proxy,
	}

	proxy.OnRequest(goproxy.ReqConditionFunc(p.requestCondition)).HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest(goproxy.ReqConditionFunc(p.requestCondition)).DoFunc(p.handleRequest)
	proxy.OnResponse(goproxy.ReqConditionFunc(p.requestCondition)).DoFunc(p.handleResponse)

	return p, nil
}

var _ http.Handler = (*Proxy)(nil)

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}

func (p *Proxy) requestCondition(req *http.Request, ctx *goproxy.ProxyCtx) bool {
	return hostMatches(req.URL, p.hosts)
}

func (p *Proxy) handleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	p.logger.Debug("incoming request", "url", req.URL)
	filePath, exists, err := getCachedFileInfo(p.dir, req)
	if err != nil {
		p.logger.Error("failed to get cache info", "error", err, "url", req.URL)
		return req, nil
	}

	if !exists {
		p.logger.Debug("cache miss", "url", req.URL)
		return req, nil
	}

	p.logger.Debug("cache hit", "url", req.URL)

	respWriter := &ResponseWriter{
		statusCode: http.StatusOK,
	}
	if req.Method == http.MethodOptions {
		header, err := readCachedHeader(filePath)
		if err != nil {
			p.logger.Error("failed to read cached header", "error", err, "url", req.URL)
		}
		respWriter.header = header
	} else {
		http.ServeFile(respWriter, req, filePath)
	}

	resp := &http.Response{
		StatusCode:       respWriter.statusCode,
		Status:           http.StatusText(respWriter.statusCode),
		TransferEncoding: req.TransferEncoding,
		Proto:            req.Proto,
		ProtoMajor:       req.ProtoMajor,
		ProtoMinor:       req.ProtoMinor,
		Header:           respWriter.header,
		Body:             io.NopCloser(&respWriter.buffer),
		ContentLength:    int64(respWriter.buffer.Len()),
		Request:          req,
	}

	if p.cors && req.Method != http.MethodOptions {
		origin := req.Header.Get("Origin")
		if origin != "" {
			resp.Header.Set("Access-Control-Allow-Origin", origin)
		}
	}

	return req, resp
}

func (p *Proxy) download(req *http.Request, finalFilePath string) {
	if _, alreadyDownloading := p.downloading.LoadOrStore(finalFilePath, true); alreadyDownloading {
		return
	}
	defer p.downloading.Delete(finalFilePath)

	if _, err := os.Stat(finalFilePath); err == nil {
		return
	}

	partialFilePath, err := getCachedFilePath(path.Join(p.dir, "partial"), req)
	if err != nil {
		p.logger.Error("failed to get cache file name", "error", err, "url", req.URL)
		return
	}

	clonedRequest := req.Clone(context.Background())
	clonedRequest.Header.Del("Range")

	p.logger.Debug("starting download", "url", clonedRequest.URL)
	resp, err := http.DefaultClient.Do(clonedRequest)
	if err != nil {
		p.logger.Error("download request failed", "error", err, "url", clonedRequest.URL)
		return
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		p.logger.Error("unexpected status from download", "status", resp.StatusCode, "url", clonedRequest.URL)
		return
	}

	if err := os.MkdirAll(filepath.Dir(partialFilePath), 0777); err != nil {
		p.logger.Error("failed to create directory", "error", err, "url", clonedRequest.URL)
		return
	}

	partialFile, err := os.Create(partialFilePath)
	if err != nil {
		p.logger.Error("failed to create file", "error", err, "url", clonedRequest.URL)
		return
	}

	defer resp.Body.Close()
	decompressor, err := getDecompressor(resp.Body, resp.Header)
	if err != nil {
		p.logger.Error("failed to get decompressor", "error", err)
		return
	}

	if _, err := io.Copy(partialFile, decompressor); err != nil {
		p.logger.Error("download failed", "error", err, "url", clonedRequest.URL)
		return
	}

	if err := os.MkdirAll(filepath.Dir(finalFilePath), 0777); err != nil {
		p.logger.Error("failed to create directory", "error", err, "url", clonedRequest.URL)
		return
	}

	if err := os.Rename(partialFilePath, finalFilePath); err != nil {
		p.logger.Error("failed to rename download", "error", err, "url", clonedRequest.URL)
		return
	}
	p.logger.Debug("download complete", "url", clonedRequest.URL)
}

func (p *Proxy) handleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil {
		p.logger.Error("unexpected nil response")
		return nil
	}
	req := resp.Request

	filePath, exists, err := getCachedFileInfo(p.dir, req)
	if err != nil {
		p.logger.Error("failed to get cache info", "error", err, "url", req.URL)
	}

	if exists {
		return resp
	}

	if req.Method == http.MethodOptions {
		if err := writeCachedHeader(filePath, resp.Header); err != nil {
			p.logger.Error("failed to write header to cache", "error", err, "url", req.URL)
		}
		return resp
	}

	if resp.StatusCode == http.StatusPartialContent {
		go p.download(req, filePath)
		return resp
	}

	defer resp.Body.Close()

	buffer := &bytes.Buffer{}
	teeReader := io.TeeReader(resp.Body, buffer)

	p.logger.Debug("caching response", "url", req.URL)

	if err := writeCached(filePath, teeReader, resp.Header); err != nil {
		p.logger.Error("failed to write to cache", "error", err, "url", req.URL)
		return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusInternalServerError, err.Error())
	}

	clonedResponse := &http.Response{}
	*clonedResponse = *resp
	clonedResponse.Body = io.NopCloser(buffer)

	return clonedResponse
}

func writeCached(filePath string, reader io.Reader, header http.Header) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0777); err != nil {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	decompressor, err := getDecompressor(reader, header)
	if err != nil {
		return err
	}

	if _, err := io.Copy(file, decompressor); err != nil {
		return err
	}
	return nil
}

func writeCachedHeader(filePath string, header http.Header) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0777); err != nil {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(header)
}

func readCachedHeader(filePath string) (http.Header, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	h := map[string][]string{}
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, err
	}

	header := http.Header{}
	for k, values := range h {
		for _, v := range values {
			header.Add(k, v)
		}
	}
	return header, nil
}

func getDecompressor(reader io.Reader, header http.Header) (io.ReadCloser, error) {
	var readCloser io.ReadCloser
	switch encoding := header.Get("Content-Encoding"); encoding {
	case "":
		if rc, ok := reader.(io.ReadCloser); ok {
			readCloser = rc
		} else {
			readCloser = io.NopCloser(reader)
		}
	case "gzip":
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		readCloser = gzipReader
	default:
		return nil, fmt.Errorf("unsupported content encoding: %s", encoding)
	}

	return readCloser, nil
}

func hostMatches(u *url.URL, hosts []string) bool {
	host, _, _ := net.SplitHostPort(u.Host)
	for _, h := range hosts {
		if host == h {
			return true
		}
	}
	return false
}

func getCachedFilePath(dir string, req *http.Request) (string, error) {
	filePath, err := RequestToFilePath(req)
	if err != nil {
		return "", err
	}
	filePath = path.Join(dir, filePath)
	return filePath, nil
}

func getCachedFileInfo(dir string, req *http.Request) (string, bool, error) {
	filePath, err := getCachedFilePath(dir, req)
	if err != nil {
		return "", false, err
	}
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		return filePath, false, nil
	} else if err != nil {
		return filePath, false, err
	}
	return filePath, true, nil
}

func RequestToFilePath(request *http.Request) (string, error) {
	if request.URL.Scheme == "" {
		return "", errors.New("url missing scheme")
	}
	if request.URL.Host == "" {
		return "", errors.New("url missing host")
	}
	escapedPath := strings.TrimPrefix(request.URL.EscapedPath(), "/")
	dir, file := filepath.Split(escapedPath)

	if request.URL.RawQuery != "" {
		hasher := sha256.New()
		hasher.Write([]byte(request.URL.RawQuery))
		hash := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
		file += "?" + hash
		if len(file) > 255 {
			file = file[:255]
		}
	}

	filePath := path.Join(request.Method, request.URL.Scheme, request.URL.Host, dir, "#"+file)
	return filePath, nil
}

func configureCertificate(certPEMBlock []byte, keyPEMBlock []byte) error {
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}
	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = cert
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
	return nil
}

type ResponseWriter struct {
	wroteHeader bool
	statusCode  int
	buffer      bytes.Buffer
	header      http.Header
}

func (w *ResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *ResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.statusCode = statusCode
		w.wroteHeader = true
	}
}

func (w *ResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.buffer.Write(data)
}

var _ http.ResponseWriter = (*ResponseWriter)(nil)
