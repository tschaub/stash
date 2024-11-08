package cache_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tschaub/stash/internal/cache"
)

func TestNewItem(t *testing.T) {
	cases := []struct {
		method string
		dir    string
		url    string
		key    string
		err    string
	}{
		{
			method: http.MethodGet,
			dir:    "base",
			url:    "https://example.com/foo/bar",
			key:    "base/GET/https/example.com/foo/#body#bar",
		},
		{
			method: http.MethodHead,
			dir:    "base",
			url:    "https://example.com/foo/bar",
			key:    "base/HEAD/https/example.com/foo/#body#bar",
		},
		{
			method: http.MethodGet,
			dir:    "base",
			url:    "https://example.com",
			key:    "base/GET/https/example.com/#body#",
		},
		{
			method: http.MethodGet,
			dir:    "base",
			url:    "https://example.com/",
			key:    "base/GET/https/example.com/#body#",
		},
		{
			method: http.MethodGet,
			dir:    "base",
			url:    "https://example.com/foo/",
			key:    "base/GET/https/example.com/foo/#body#",
		},
		{
			method: http.MethodGet,
			dir:    "base",
			url:    "https://example.com/foo/bar?bam=baz",
			key:    "base/GET/https/example.com/foo/#body#bar?Zr0Oj6-1pxy_lUJzgcb3eJWPYD1I-vlgv0wl_Vk5g6w=",
		},
		{
			method: http.MethodGet,
			dir:    "base",
			url:    "https://example.com/foo/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?bam=baz",
			key:    "base/GET/https/example.com/foo/#body#xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?Zr0Oj6-1pxy_lU",
		},
		{
			method: http.MethodGet,
			url:    "/foo/bar",
			err:    "url missing scheme",
		},
		{
			method: http.MethodGet,
			url:    "./foo/bar",
			err:    "url missing scheme",
		},
		{
			method: http.MethodGet,
			url:    "http:///foo/bar",
			err:    "url missing host",
		},
	}

	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			u, err := url.Parse(c.url)
			if err != nil {
				require.EqualError(t, err, c.err)
				return
			}

			request := &http.Request{URL: u, Method: c.method}
			item, err := cache.NewItem(c.dir, request)
			if err != nil {
				require.EqualError(t, err, c.err)
				return
			}

			assert.Equal(t, c.key, item.Key())
		})
	}

}
