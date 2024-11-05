package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/alecthomas/kong"
	_ "github.com/joho/godotenv/autoload"
	"github.com/tschaub/stash/internal/proxy"
)

func main() {
	ctx := kong.Parse(&Stash{}, kong.UsageOnError())
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

type Stash struct {
	Port      int      `help:"Listen on this port." default:"9999" env:"STASH_PORT"`
	Dir       string   `help:"Path to cache directory" type:"path" default:".stash" env:"STASH_DIR"`
	Hosts     []string `help:"Cache responses from these hosts" env:"STASH_HOSTS"`
	CertFile  string   `help:"Path to CA certificate file" type:"existingfile" required:"" env:"STASH_CERT_FILE"`
	KeyFile   string   `help:"Path to CA private key file" type:"existingfile" required:"" env:"STASH_KEY_FILE"`
	LogLevel  string   `help:"Log level" enum:"debug,info,warn,error" default:"info" env:"STASH_LOG_LEVEL"`
	LogFormat string   `help:"Log format" enum:"text,json" default:"text" env:"STASH_LOG_FORMAT"`
}

func (s *Stash) Run() error {
	logger, err := configureLogger(s.LogLevel, s.LogFormat)
	if err != nil {
		return err
	}

	if dirInfo, err := os.Stat(s.Dir); err == nil {
		if !dirInfo.IsDir() {
			return fmt.Errorf("%q exists but is not a directory", s.Dir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("trouble accessing cache directory: %w", err)
	}

	cert, key, err := loadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		return fmt.Errorf("error loading CA certificate/key: %w", err)
	}

	stash := &proxy.Proxy{
		Certificate: cert,
		Key:         key,
		Logger:      logger,
		Dir:         s.Dir,
		Hosts:       s.Hosts,
	}

	addr := fmt.Sprintf("127.0.0.1:%d", s.Port)
	logger.Info("starting proxy server", "address", addr)
	if err := http.ListenAndServe(addr, stash); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
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
