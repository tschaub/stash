package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/elazarl/goproxy"
	"github.com/tschaub/stash/internal/cache"
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

func (p *Proxy) cacheDir() string {
	return path.Join(p.dir, "cache")
}

func (p *Proxy) tempDir() string {
	return path.Join(p.dir, "temp")
}

func (p *Proxy) requestCondition(req *http.Request, ctx *goproxy.ProxyCtx) bool {
	return hostMatches(req.URL, p.hosts)
}

func (p *Proxy) handleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	p.logger.Debug("incoming request", "url", req.URL, "method", req.Method)

	cacheItem, err := cache.NewItem(p.cacheDir(), req)
	if err != nil {
		p.logger.Error("failed to get new cache item", "error", err, "url", req.URL, "method", req.Method)
		return req, nil
	}

	exists, err := cacheItem.Exists()
	if err != nil {
		p.logger.Error("failed to check cache item existence", "error", err, "url", req.URL, "method", req.Method)
		return req, nil
	}

	if !exists {
		p.logger.Debug("cache miss", "url", req.URL, "method", req.Method)
		return req, nil
	}

	p.logger.Debug("cache hit", "url", req.URL, "method", req.Method)

	resp, err := cacheItem.Respond(req)
	if err != nil {
		p.logger.Error("failed to generate response from cache item", "error", err, "url", req.URL, "method", req.Method)
	}

	if p.cors && req.Method != http.MethodOptions {
		if origin := req.Header.Get("Origin"); origin != "" {
			resp.Header.Set("Access-Control-Allow-Origin", origin)
		}
	}

	return req, resp
}

func (p *Proxy) handleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil {
		p.logger.Error("unexpected nil response")
		return nil
	}
	req := resp.Request

	cacheItem, err := cache.NewItem(p.cacheDir(), req)
	if err != nil {
		p.logger.Error("failed to get cache item", "error", err, "url", req.URL, "method", req.Method)
		return resp
	}

	exists, err := cacheItem.Exists()
	if err != nil {
		p.logger.Error("failed to check cache item existence", "error", err, "url", req.URL, "method", req.Method)
		return resp
	}

	if exists {
		return resp
	}

	meta := &cache.Meta{Header: resp.Header, StatusCode: resp.StatusCode}

	if req.Method == http.MethodOptions || req.Method == http.MethodHead {
		if err := cacheItem.Write(nil, meta); err != nil {
			p.logger.Error("failed to write header to cache", "error", err, "url", req.URL, "method", req.Method)
		}
		return resp
	}

	if resp.StatusCode == http.StatusPartialContent {
		go p.download(req)
		return resp
	}

	defer resp.Body.Close()
	buffer := &bytes.Buffer{}
	teeReader := io.TeeReader(resp.Body, buffer)

	p.logger.Debug("caching response", "url", req.URL, "method", req.Method)

	clonedResponse := &http.Response{}
	*clonedResponse = *resp

	if err := cacheItem.Write(teeReader, meta); err != nil {
		p.logger.Error("failed to write to cache", "error", err, "url", req.URL, "method", req.Method)
		clonedResponse.Body = io.NopCloser(io.MultiReader(buffer, resp.Body))
		return clonedResponse
	}

	clonedResponse.Body = io.NopCloser(buffer)
	return clonedResponse
}

func (p *Proxy) download(req *http.Request) {
	tempCacheItem, err := cache.NewItem(p.tempDir(), req)
	if err != nil {
		p.logger.Error("download failed", "error", err, "url", req.URL, "method", req.Method)
	}

	cacheKey := tempCacheItem.Key()
	if _, alreadyDownloading := p.downloading.LoadOrStore(cacheKey, true); alreadyDownloading {
		p.logger.Debug("already downloading", "url", req.URL, "method", req.Method)
		return
	}
	defer p.downloading.Delete(cacheKey)

	clonedRequest := req.Clone(context.Background())
	clonedRequest.Header.Del("Range")

	p.logger.Debug("starting download", "url", clonedRequest.URL, "method", req.Method)
	resp, err := http.DefaultClient.Do(clonedRequest)
	if err != nil {
		p.logger.Error("download request failed", "error", err, "url", clonedRequest.URL, "method", req.Method)
		return
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		p.logger.Error("unexpected status from download", "status", resp.StatusCode, "url", clonedRequest.URL, "method", req.Method)
		return
	}

	defer resp.Body.Close()
	meta := &cache.Meta{Header: resp.Header, StatusCode: resp.StatusCode}
	if err := tempCacheItem.Write(resp.Body, meta); err != nil {
		p.logger.Error("failed to cache download", "error", err, "url", clonedRequest.URL, "method", req.Method)
	}

	if _, err := tempCacheItem.Move(p.cacheDir()); err != nil {
		p.logger.Error("failed to rename download", "error", err, "url", clonedRequest.URL, "method", req.Method)
	}
	p.logger.Debug("download complete", "url", clonedRequest.URL, "method", req.Method)
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

func (w *ResponseWriter) applyHeader(header http.Header) {
	for k, values := range header {
		w.header.Del(k)
		for _, v := range values {
			w.header.Add(k, v)
		}
	}
}

var _ http.ResponseWriter = (*ResponseWriter)(nil)