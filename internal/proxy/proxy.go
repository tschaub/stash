package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type Proxy struct {
	Certificate *x509.Certificate
	Key         any
	Logger      *slog.Logger
	Dir         string
	Hosts       []string
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

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	p.Logger.Debug("request received", "method", req.Method, "url", req.URL.String())

	if req.Method == http.MethodConnect {
		p.hijackConnect(w, req)
		return
	}

	p.serveHttp(w, req)
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

func getCachedFile(request *http.Request, dir string) (string, bool, error) {
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
	useCache bool
	filePath string
	exists   bool
}

var skipCache = &CacheInfo{}

func (p *Proxy) getCacheInfo(request *http.Request) (*CacheInfo, error) {
	useCache := hostMatches(request.URL, p.Hosts)
	if !useCache {
		return skipCache, nil
	}

	filePath, exists, err := getCachedFile(request, p.Dir)
	if err != nil {
		return nil, err
	}
	info := &CacheInfo{
		useCache: true,
		filePath: filePath,
		exists:   exists,
	}
	return info, nil
}

func (p *Proxy) serveHttp(w http.ResponseWriter, req *http.Request) {
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		p.Logger.Debug("unsupported protocol", "scheme", req.URL.Scheme)
		http.Error(w, "unsupported protocol scheme "+req.URL.Scheme, http.StatusBadRequest)
		return
	}

	client := &http.Client{}
	req.RequestURI = ""
	removeHopHeaders(req.Header)
	removeConnectionHeaders(req.Header)

	cacheInfo, err := p.getCacheInfo(req)
	if err != nil {
		p.Logger.Error("trouble getting cached file", "error", err, "url", req.URL.String())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if cacheInfo.useCache && cacheInfo.exists {
		p.Logger.Debug("serving cached file", "file", cacheInfo.filePath, "url", req.URL.String())
		http.ServeFile(w, req, cacheInfo.filePath)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		// maybe offline
		p.Logger.Debug("failed to make request", "error", err, "url", req.URL.String())
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if cacheInfo.useCache && (resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices) {
		p.Logger.Info("skipping cache due to status", "status", resp.StatusCode, "url", req.URL.String())
		cacheInfo.useCache = false
	}

	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	removeConnectionHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)

	if !cacheInfo.useCache {
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			p.Logger.Error("failed to copy body to response", "error", err, "url", req.URL.String())
		}
		p.Logger.Debug("proxied response without caching", "url", req.URL)
		return
	}

	if err := os.MkdirAll(filepath.Dir(cacheInfo.filePath), 0777); err != nil {
		p.Logger.Error("failed to create directory", "error", err, "path", filepath.Dir(cacheInfo.filePath))
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	file, err := os.Create(cacheInfo.filePath)
	if err != nil {
		p.Logger.Error("failed to create file", "error", err, "path", cacheInfo.filePath)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.WriteHeader(resp.StatusCode)
	reader := io.TeeReader(resp.Body, w)

	switch encoding := resp.Header.Get("Content-Encoding"); encoding {
	case "":
		// no compression
	case "gzip":
		r, err := gzip.NewReader(reader)
		if err != nil {
			p.Logger.Error("failed to create gzip reader", "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		defer r.Close()
		reader = r
	default:
		p.Logger.Error("unsupported content encoding", "encoding", encoding)
	}

	p.Logger.Debug("caching response", "file", cacheInfo.filePath, "url", req.URL.String())
	if _, err := io.Copy(file, reader); err != nil {
		p.Logger.Error("failed to copy body to response", "error", err)
	}
}

// hijackConnect implements the MITM proxy for CONNECT tunnels.
func (p *Proxy) hijackConnect(w http.ResponseWriter, proxyReq *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		p.Logger.Error("http server doesn't support hijacking connection")
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		p.Logger.Error("http hijacking failed")
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	host, _, err := net.SplitHostPort(proxyReq.Host)
	if err != nil {
		p.Logger.Error("error splitting host/port", "error", err)
		return
	}

	pemCert, pemKey, err := createCert([]string{host}, p.Certificate, p.Key, 240)
	if err != nil {
		p.Logger.Error("error creating certificate", "error", err)
		return
	}
	tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		p.Logger.Error("error parsing key pair", "error", err)
		return
	}

	statusLine := fmt.Sprintf("HTTP/%d.%d 200 OK\r\n\r\n", proxyReq.ProtoMajor, proxyReq.ProtoMinor)
	if _, err := clientConn.Write([]byte(statusLine)); err != nil {
		p.Logger.Error("error writing status to client", "error", err)
		return
	}

	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		MinVersion:               tls.VersionTLS13,
		Certificates:             []tls.Certificate{tlsCert},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	connReader := bufio.NewReader(tlsConn)

	// Run the proxy in a loop until the client closes the connection.
	for {
		r, err := http.ReadRequest(connReader)
		if err == io.EOF {
			break
		}
		if err != nil {
			p.Logger.Error("error reading from connection", "error", err)
			return
		}

		if err := changeRequestToTarget(r, proxyReq.Host); err != nil {
			p.Logger.Error("failed to rewrite request", "error", err)
			return
		}

		cacheInfo, err := p.getCacheInfo(r)
		if err != nil {
			p.Logger.Error("trouble getting cached file", "error", err, "url", r.URL.String())
			return
		}

		if cacheInfo.useCache && cacheInfo.exists {
			p.Logger.Debug("serving cached file", "file", cacheInfo.filePath, "url", r.URL.String())

			pw := &ResponseWriter{}
			http.ServeFile(pw, r, cacheInfo.filePath)
			resp := &http.Response{
				StatusCode:    pw.statusCode,
				Status:        http.StatusText(pw.statusCode),
				Proto:         r.Proto,
				ProtoMajor:    r.ProtoMajor,
				ProtoMinor:    r.ProtoMinor,
				Header:        pw.header,
				Body:          io.NopCloser(&pw.buffer),
				ContentLength: int64(pw.buffer.Len()),
				Request:       r,
			}
			if err := resp.Write(tlsConn); err != nil {
				p.Logger.Error("error writing cached response", "error", err)
			}
			continue
		}

		p.Logger.Debug("forwarding request", "method", r.Method, "url", r.URL)

		removeHopHeaders(r.Header)
		removeConnectionHeaders(r.Header)

		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			p.Logger.Error("error forwarding request", "error", err, "url", r.URL)
			return
		}

		removeHopHeaders(resp.Header)
		removeConnectionHeaders(resp.Header)

		if !cacheInfo.useCache {
			if err := resp.Write(tlsConn); err != nil {
				p.Logger.Error("error writing response", "error", err, "url", r.URL)
				return
			}
			continue
		}

		buffer := &bytes.Buffer{}
		teeReader := io.TeeReader(resp.Body, buffer)

		clonedResponse := &http.Response{}
		*clonedResponse = *resp

		clonedResponse.Body = struct {
			io.Reader
			io.Closer
		}{
			teeReader,
			r.Body,
		}

		if err := clonedResponse.Write(tlsConn); err != nil {
			p.Logger.Error("error writing response", "error", err, "url", r.URL)
			return
		}

		p.Logger.Debug("caching response", "file", cacheInfo.filePath, "url", r.URL)
		if err := p.writeCached(cacheInfo.filePath, buffer, r.Header); err != nil {
			p.Logger.Error("failed to cache response", "error", err, "file", cacheInfo.filePath)
		}
	}
}

func (p *Proxy) writeCached(filePath string, reader io.Reader, header http.Header) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0777); err != nil {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	decompressor, err := p.getDecompressor(reader, header)
	if err != nil {
		return err
	}

	if _, err := io.Copy(file, decompressor); err != nil {
		return err
	}
	return nil
}

func (p *Proxy) getDecompressor(reader io.Reader, header http.Header) (io.ReadCloser, error) {
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

func createCert(dnsNames []string, parent *x509.Certificate, parentKey crypto.PrivateKey, hoursValid int) ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Sample MITM proxy"},
		},
		DNSNames:  dnsNames,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Duration(hoursValid) * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, parentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create certificate: %w", err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return nil, nil, errors.New("failed to encode certificate to PEM")
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to marshal private key: %w", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		return nil, nil, fmt.Errorf("failed to encode key to PEM")
	}

	return pemCert, pemKey, nil
}

func changeRequestToTarget(req *http.Request, targetHost string) error {
	targetUrl, err := addrToUrl(targetHost)
	if err != nil {
		return err
	}
	targetUrl.Path = req.URL.Path
	targetUrl.RawQuery = req.URL.RawQuery
	req.URL = targetUrl
	// Make sure this is unset for sending the request through a client
	req.RequestURI = ""

	return nil
}

func addrToUrl(addr string) (*url.URL, error) {
	if !strings.HasPrefix(addr, "https") {
		addr = "https://" + addr
	}
	return url.Parse(addr)
}

// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // spelling per https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func copyHeader(dst http.Header, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func removeHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

// removeConnectionHeaders removes hop-by-hop headers listed in the "Connection"
// header of h. See RFC 7230, section 6.1
func removeConnectionHeaders(h http.Header) {
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = strings.TrimSpace(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
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
