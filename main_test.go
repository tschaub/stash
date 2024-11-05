package main

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUrlToFilePath(t *testing.T) {
	cases := []struct {
		u string
		p string
		e string
	}{
		{
			u: "https://example.com/foo/bar",
			p: "https/example.com/foo/bar",
		},
		{
			u: "https://example.com",
			p: "https/example.com/?",
		},
		{
			u: "https://example.com/",
			p: "https/example.com/?",
		},
		{
			u: "https://example.com/foo/",
			p: "https/example.com/foo/?",
		},
		{
			u: "/foo/bar",
			e: "url missing scheme",
		},
		{
			u: "./foo/bar",
			e: "url missing scheme",
		},
		{
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

			p, err := urlToFilePath(u)
			if err != nil {
				require.EqualError(t, err, c.e)
				return
			}

			assert.Equal(t, c.p, p)
		})
	}

}
