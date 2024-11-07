package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
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
	logger *slog.Logger
	dir    string
	hosts  []string
	cors   bool
	proxy  *goproxy.ProxyHttpServer
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
	cacheInfo, err := getCacheInfo(p.dir, req)
	if err != nil {
		p.logger.Error("failed to get cache info", "error", err, "url", req.URL)
		return req, nil
	}

	if !cacheInfo.exists {
		p.logger.Debug("cache miss", "url", req.URL)
		return req, nil
	}

	p.logger.Debug("cache hit", "file", cacheInfo.filePath, "url", req.URL)

	respWriter := &ResponseWriter{}
	http.ServeFile(respWriter, req, cacheInfo.filePath)

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

	if p.cors {
		headers := resp.Header
		headers.Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
	}

	return req, resp
}

func (p *Proxy) handleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil {
		p.logger.Error("unexpected nil response")
		return nil
	}
	req := resp.Request

	cacheInfo, err := getCacheInfo(p.dir, req)
	if err != nil {
		p.logger.Error("failed to get cache info", "error", err, "url", req.URL)
	}

	if cacheInfo.exists {
		return resp
	}

	defer resp.Body.Close()

	buffer := &bytes.Buffer{}
	teeReader := io.TeeReader(resp.Body, buffer)

	p.logger.Debug("caching response", "file", cacheInfo.filePath, "url", req.URL)

	if err := writeCached(cacheInfo.filePath, teeReader, resp.Header); err != nil {
		p.logger.Error("failed to write to cache", "file", cacheInfo.filePath, "url", req.URL)
		return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusInternalServerError, err.Error())
	}

	clonedResponse := &http.Response{}
	*clonedResponse = *resp
	clonedResponse.Body = io.NopCloser(buffer)

	return clonedResponse
}

func getCacheInfo(dir string, req *http.Request) (*CacheInfo, error) {
	filePath, exists, err := getCachedFile(dir, req)
	if err != nil {
		return nil, err
	}

	info := &CacheInfo{
		filePath: filePath,
		exists:   exists,
	}
	return info, nil
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

func getCachedFile(dir string, request *http.Request) (string, bool, error) {
	filePath, err := RequestToFilePath(request)
	if err != nil {
		return "", false, err
	}
	filePath = path.Join(dir, filePath)
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		return filePath, false, nil
	} else if err != nil {
		return filePath, false, err
	}
	return filePath, true, nil
}

type CacheInfo struct {
	filePath string
	exists   bool
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

	filePath := path.Join(request.Method, request.URL.Scheme, request.URL.Host, dir, "#"+file)
	if request.URL.RawQuery != "" {
		filePath += "?" + request.URL.RawQuery
	}
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
