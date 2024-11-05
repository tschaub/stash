package main

import (
	"bufio"
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
	"log"
	"log/slog"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultCertFile = "/Users/tim/Library/Application Support/mkcert/rootCA.pem"
	defaultKeyFile  = "/Users/tim/Library/Application Support/mkcert/rootCA-key.pem"
)

func init() {
	_ = mime.AddExtensionType(".json", "application/geo+json")
}

type Config struct {
	Port      int
	CertFile  string
	KeyFile   string
	LogLevel  string
	LogFormat string
	Dir       string
	Hosts     []string
}

type ProxyConfig struct {
	CertFile string
	KeyFile  string
	Logger   *slog.Logger
	Dir      string
	Hosts    []string
}

func main() {
	config := &Config{
		Port:      9999,
		CertFile:  defaultCertFile,
		KeyFile:   defaultKeyFile,
		LogLevel:  "info",
		LogFormat: "text",
		Dir:       "cache",
		Hosts:     []string{"example.com"},
	}

	logger, err := configureLogger(config.LogLevel, config.LogFormat)
	if err != nil {
		log.Fatal(err)
	}

	proxyConfig := &ProxyConfig{
		CertFile: config.CertFile,
		KeyFile:  config.KeyFile,
		Logger:   logger,
		Dir:      config.Dir,
		Hosts:    config.Hosts,
	}
	proxy, err := NewProxy(proxyConfig)
	if err != nil {
		logger.Error("failed to create proxy", "error", err)
		os.Exit(1)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	logger.Info("starting proxy server", "address", addr)
	if err := http.ListenAndServe(addr, proxy); err != nil {
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}

func configureLogger(logLevel string, logFormat string) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		return nil, fmt.Errorf("unsupported log level '%s'", logLevel)
	}

	switch logFormat {
	case "json":
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
		return logger, nil
	case "text":
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
		return logger, nil
	default:
		return nil, fmt.Errorf("unsupported log format '%s'", logFormat)
	}
}

// createCert creates a new certificate/private key pair for the given domains,
// signed by the parent/parentKey certificate. hoursValid is the duration of
// the new certificate's validity.
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

// loadX509KeyPair loads a certificate/key pair from files, and unmarshals them
// into data structures from the x509 package. Note that private key types in Go
// don't have a shared named interface and use `any` (for backwards
// compatibility reasons).
func loadX509KeyPair(certFile, keyFile string) (cert *x509.Certificate, key any, err error) {
	cf, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}

	kf, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(cf)
	cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(kf)
	key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// changeRequestToTarget modifies req to be re-routed to the given target;
// the target should be taken from the Host of the original tunnel (CONNECT)
// request.
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

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
// Note: this may be out of date, see RFC 7230 Section 6.1
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

func NewProxy(config *ProxyConfig) (*Proxy, error) {
	caCert, caKey, err := loadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("Error loading CA certificate/key: %w", err)
	}

	proxy := &Proxy{
		caCert: caCert,
		caKey:  caKey,
		logger: config.Logger,
		dir:    config.Dir,
		hosts:  config.Hosts,
	}
	return proxy, nil
}

type Proxy struct {
	caCert *x509.Certificate
	caKey  any
	logger *slog.Logger
	dir    string
	hosts  []string
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	p.logger.Debug("request received", "method", req.Method, "url", req.URL.String())

	if req.Method == http.MethodConnect {
		p.hijackConnect(w, req)
		return
	}

	p.serveHttp(w, req)
}

func (p *Proxy) serveHttp(w http.ResponseWriter, req *http.Request) {
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		p.logger.Debug("unsupported protocol", "scheme", req.URL.Scheme)
		http.Error(w, "unsupported protocol scheme "+req.URL.Scheme, http.StatusBadRequest)
		return
	}

	client := &http.Client{}
	req.RequestURI = ""
	removeHopHeaders(req.Header)
	removeConnectionHeaders(req.Header)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		appendHostToXForwardHeader(req.Header, clientIP)
	}

	useCache := false
	for _, host := range p.hosts {
		if req.URL.Host == host {
			useCache = true
			break
		}
	}

	var filePath string
	if useCache {
		var err error
		filePath, err = urlToFilePath(req.URL)
		if err != nil {
			p.logger.Error("error creating file path", "error", err, "url", req.URL.String())
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		filePath = path.Join(p.dir, filePath)
		if _, err := os.Stat(filePath); err == nil {
			p.logger.Debug("serving cached file", "file", filePath, "url", req.URL.String())
			http.ServeFile(w, req, filePath)
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			p.logger.Error("trouble checking file", "error", err, "file", filePath)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		// maybe offline
		p.logger.Debug("failed to make request", "error", err, "url", req.URL.String())
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		p.logger.Info("skipping cache due to status", "status", resp.StatusCode, "url", req.URL.String())
		useCache = false
	}

	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	removeConnectionHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)

	if !useCache {
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			p.logger.Error("failed to copy body to response", "error", err, "url", req.URL.String())
		}
		p.logger.Debug("proxied response without caching", "url", req.URL)
		return
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0777); err != nil {
		p.logger.Error("failed to create directory", "error", err, "path", filepath.Dir(filePath))
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	file, err := os.Create(filePath)
	if err != nil {
		p.logger.Error("failed to create file", "error", err, "path", filePath)
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
			p.logger.Error("failed to create gzip reader", "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		defer r.Close()
		reader = r
	default:
		p.logger.Error("unsupported content encoding", "encoding", encoding)
	}

	p.logger.Debug("caching response", "file", filePath, "url", req.URL.String())
	if _, err := io.Copy(file, reader); err != nil {
		p.logger.Error("failed to copy body to response", "error", err)
	}
}

// hijackConnect implements the MITM proxy for CONNECT tunnels.
func (p *Proxy) hijackConnect(w http.ResponseWriter, proxyReq *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error("http server doesn't support hijacking connection")
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		p.logger.Error("http hijacking failed")
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	host, _, err := net.SplitHostPort(proxyReq.Host)
	if err != nil {
		p.logger.Error("error splitting host/port", "error", err)
		return
	}

	pemCert, pemKey, err := createCert([]string{host}, p.caCert, p.caKey, 240)
	if err != nil {
		p.logger.Error("error creating certificate", "error", err)
		return
	}
	tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		p.logger.Error("error parsing key pair", "error", err)
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		p.logger.Error("error writing status to client", "error", err)
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
			p.logger.Error("error reading from connection", "error", err)
			return
		}

		if err := changeRequestToTarget(r, proxyReq.Host); err != nil {
			p.logger.Error("failed to rewrite request", "error", err)
			return
		}

		p.logger.Debug("forwarding request", "method", r.Method, "url", r.URL)

		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			p.logger.Error("error forwarding request", "error", err)
			return
		}

		defer resp.Body.Close()

		if err := resp.Write(tlsConn); err != nil {
			p.logger.Error("error writing response back", "error", err)
		}
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

func appendHostToXForwardHeader(header http.Header, host string) {
	if prior, ok := header["X-Forwarded-For"]; ok {
		host = strings.Join(prior, ", ") + ", " + host
	}
	header.Set("X-Forwarded-For", host)
}

func urlToFilePath(u *url.URL) (string, error) {
	if u.Scheme == "" {
		return "", errors.New("url missing scheme")
	}
	if u.Host == "" {
		return "", errors.New("url missing host")
	}
	if u.RawQuery != "" {
		return "", errors.New("url with query cannot be converted to a path")
	}
	escapedPath := strings.TrimPrefix(u.EscapedPath(), "/")
	if escapedPath == "" || strings.HasSuffix(escapedPath, "/") {
		escapedPath += "?"
	}
	return path.Join(u.Scheme, u.Host, escapedPath), nil
}
