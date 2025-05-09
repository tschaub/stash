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
	Dir         string
	Hosts       []string
}

type Proxy struct {
	logger      *slog.Logger
	dir         string
	hosts       []string
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
	ctx.UserData = cacheItem

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

	if origin := req.Header.Get("Origin"); origin != "" {
		if allowed := resp.Header.Get("Access-Control-Allow-Origin"); allowed != origin {
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

	var cacheItem *cache.Item
	if i, ok := ctx.UserData.(*cache.Item); ok && i != nil {
		cacheItem = i
	} else {
		p.logger.Error("missing cache item in response handler user data", "url", req.URL)
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
		go p.download(req, cacheItem)
		return resp
	}

	defer func() { _ = resp.Body.Close() }()
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

func (p *Proxy) download(req *http.Request, cacheItem *cache.Item) {
	tempCacheItem := cacheItem.Rebase(p.tempDir())

	cacheKey := tempCacheItem.Key()
	if _, alreadyDownloading := p.downloading.LoadOrStore(cacheKey, true); alreadyDownloading {
		p.logger.Debug("already downloading", "url", req.URL, "method", req.Method)
		return
	}
	defer p.downloading.Delete(cacheKey)

	clonedRequest := req.Clone(context.Background())
	clonedRequest.Header.Del("Range")

	p.logger.Info("starting download", "url", clonedRequest.URL, "method", req.Method)
	resp, err := http.DefaultClient.Do(clonedRequest)
	if err != nil {
		p.logger.Error("download request failed", "error", err, "url", clonedRequest.URL, "method", req.Method)
		return
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		p.logger.Error("unexpected status from download", "status", resp.StatusCode, "url", clonedRequest.URL, "method", req.Method)
		return
	}

	defer func() { _ = resp.Body.Close() }()
	meta := &cache.Meta{Header: resp.Header, StatusCode: resp.StatusCode}
	if err := tempCacheItem.Write(resp.Body, meta); err != nil {
		p.logger.Error("failed to cache download", "error", err, "url", clonedRequest.URL, "method", req.Method)
	}

	if _, err := tempCacheItem.Move(p.cacheDir()); err != nil {
		p.logger.Error("failed to rename download", "error", err, "url", clonedRequest.URL, "method", req.Method)
	}
	p.logger.Info("download complete", "url", clonedRequest.URL, "method", req.Method)
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
