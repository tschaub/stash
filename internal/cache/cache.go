package cache

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
)

type Item struct {
	baseDir     string
	relBodyPath string
	relMetaPath string
}

func (i *Item) Key() string {
	return i.bodyPath()
}

const maxFileNameLength = 255

func NewItem(cacheDir string, req *http.Request) (*Item, error) {
	if req.URL.Scheme == "" {
		return nil, errors.New("url missing scheme")
	}
	if req.URL.Host == "" {
		return nil, errors.New("url missing host")
	}

	dir, file := filepath.Split(req.URL.EscapedPath())

	extra := false
	hasher := sha256.New()
	if req.URL.RawQuery != "" {
		hasher.Write([]byte(req.URL.RawQuery))
		extra = true
	}

	if req.Body != nil {
		body := req.Body
		buffer := &bytes.Buffer{}
		if _, err := io.Copy(buffer, body); err != nil {
			req.Body = struct {
				io.Closer
				io.Reader
			}{
				Closer: body,
				Reader: io.MultiReader(buffer, body),
			}
			return nil, err
		}

		defer func() { _ = body.Close() }()
		req.Body = io.NopCloser(buffer)
		if buffer.Len() > 0 {
			hasher.Write(buffer.Bytes())
			extra = true
		}
	}

	if extra {
		file += "?" + base64.URLEncoding.EncodeToString(hasher.Sum(nil))
		if len(file) > maxFileNameLength {
			file = file[:maxFileNameLength]
		}
	}

	relPath := path.Join(req.Method, req.URL.Scheme, req.URL.Host, dir)
	item := &Item{
		baseDir:     cacheDir,
		relBodyPath: path.Join(relPath, "#body#"+file),
		relMetaPath: path.Join(relPath, "#meta#"+file),
	}
	return item, nil
}

func (i *Item) bodyPath() string {
	return path.Join(i.baseDir, i.relBodyPath)
}

func (i *Item) metaPath() string {
	return path.Join(i.baseDir, i.relMetaPath)
}

func (i *Item) Respond(req *http.Request) (*http.Response, error) {
	meta, err := readMeta(i.metaPath())
	if err != nil {
		return nil, err
	}

	respWriter := &responseWriter{}
	if req.Method == http.MethodOptions || req.Method == http.MethodHead {
		respWriter.statusCode = meta.StatusCode
		respWriter.header = meta.Header
	} else {
		http.ServeFile(respWriter, req, i.bodyPath())
		respWriter.applyHeader(meta.Header)
	}

	resp := &http.Response{
		StatusCode:    respWriter.statusCode,
		Status:        http.StatusText(respWriter.statusCode),
		Header:        respWriter.header,
		Body:          io.NopCloser(&respWriter.buffer),
		ContentLength: int64(respWriter.buffer.Len()),
		Request:       req,
	}

	return resp, nil
}

func (i *Item) Exists() (bool, error) {
	for _, p := range []string{i.bodyPath(), i.metaPath()} {
		_, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func (i *Item) Write(body io.Reader, meta *Meta) error {
	if err := writeMeta(i.metaPath(), meta); err != nil {
		return err
	}

	bodyPath := i.bodyPath()
	if err := os.MkdirAll(filepath.Dir(bodyPath), 0777); err != nil {
		return err
	}

	file, err := os.Create(bodyPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	if body == nil {
		return nil
	}

	decompressor, err := getDecompressor(body, meta.Header)
	if err != nil {
		return err
	}

	if _, err := io.Copy(file, decompressor); err != nil {
		return err
	}
	return nil
}

func (i *Item) Move(dir string) (*Item, error) {
	newItem := &Item{
		baseDir:     dir,
		relBodyPath: i.relBodyPath,
		relMetaPath: i.relMetaPath,
	}

	if err := os.MkdirAll(filepath.Dir(newItem.bodyPath()), 0777); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(newItem.metaPath()), 0777); err != nil {
		return nil, err
	}

	if err := os.Rename(i.bodyPath(), newItem.bodyPath()); err != nil {
		return nil, err
	}

	if err := os.Rename(i.metaPath(), newItem.metaPath()); err != nil {
		return nil, err
	}

	return newItem, nil
}

func (i *Item) Rebase(dir string) *Item {
	return &Item{
		baseDir:     dir,
		relBodyPath: i.relBodyPath,
		relMetaPath: i.relMetaPath,
	}
}

type Meta struct {
	Header     http.Header
	StatusCode int
}

func writeMeta(filePath string, meta *Meta) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0777); err != nil {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	return encoder.Encode(meta)
}

func readMeta(filePath string) (*Meta, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	meta := &Meta{}
	if err := json.Unmarshal(data, meta); err != nil {
		return nil, err
	}
	return meta, nil
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

type responseWriter struct {
	wroteHeader bool
	statusCode  int
	buffer      bytes.Buffer
	header      http.Header
}

func (w *responseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.statusCode = statusCode
		w.wroteHeader = true
	}
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.buffer.Write(data)
}

var selectHeaders = []string{
	"Access-Control-Allow-Credentials",
	"Access-Control-Allow-Headers",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Origin",
	"Content-Type",
}

func (w *responseWriter) applyHeader(header http.Header) {
	for _, k := range selectHeaders {
		values := header.Values(k)
		if len(values) != 0 {
			w.header.Del(k)
			for _, v := range values {
				w.header.Add(k, v)
			}
		}
	}
}

var _ http.ResponseWriter = (*responseWriter)(nil)
