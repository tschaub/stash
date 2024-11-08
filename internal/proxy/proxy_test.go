package proxy_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tschaub/stash/internal/proxy"
)

func TestUrlToFilePath(t *testing.T) {
	cases := []struct {
		m string
		u string
		p string
		e string
	}{
		{
			m: http.MethodGet,
			u: "https://example.com/foo/bar",
			p: "GET/https/example.com/foo/#bar",
		},
		{
			m: http.MethodHead,
			u: "https://example.com/foo/bar",
			p: "HEAD/https/example.com/foo/#bar",
		},
		{
			m: http.MethodGet,
			u: "https://example.com",
			p: "GET/https/example.com/#",
		},
		{
			m: http.MethodGet,
			u: "https://example.com/",
			p: "GET/https/example.com/#",
		},
		{
			m: http.MethodGet,
			u: "https://example.com/foo/",
			p: "GET/https/example.com/foo/#",
		},
		{
			m: http.MethodGet,
			u: "https://example.com/foo/bar?bam=baz",
			p: "GET/https/example.com/foo/#bar?Zr0Oj6-1pxy_lUJzgcb3eJWPYD1I-vlgv0wl_Vk5g6w=",
		},
		{
			m: http.MethodGet,
			u: "https://example.com/foo/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?bam=baz",
			p: "GET/https/example.com/foo/#xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?Zr0Oj6-1pxy_lU",
		},
		{
			m: http.MethodGet,
			u: "/foo/bar",
			e: "url missing scheme",
		},
		{
			m: http.MethodGet,
			u: "./foo/bar",
			e: "url missing scheme",
		},
		{
			m: http.MethodGet,
			u: "http:///foo/bar",
			e: "url missing host",
		},
	}

	for _, c := range cases {
		t.Run(c.u, func(t *testing.T) {
			u, err := url.Parse(c.u)
			if err != nil {
				require.EqualError(t, err, c.e)
				return
			}

			request := &http.Request{URL: u, Method: c.m}
			p, err := proxy.RequestToFilePath(request)
			if err != nil {
				require.EqualError(t, err, c.e)
				return
			}

			assert.Equal(t, c.p, p)
		})
	}

}
