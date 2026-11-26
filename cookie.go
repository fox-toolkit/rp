// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

package rp

import (
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

const (
	cookiePrefix   = "__Host-Http-"
	frontendCookie = cookiePrefix + "BFF"
	proxyCookie    = cookiePrefix + "Proxy"
	// sharedCookie starts the name of the session cookie of a [Proxy] with a cookie domain. The __Host- prefix forbids
	// the Domain attribute.
	sharedCookie = "__Http-Proxy"
	// maxChunkSize is the maximum length of a cookie value. It leaves room for the name and attributes within the
	// 4096 bytes that browsers accept for a cookie.
	maxChunkSize = 3800
)

var (
	errNoCookie      = errors.New("no cookie")
	errInvalidCookie = errors.New("invalid cookie")
)

// cookieSpec is an encrypted cookie, split into chunks named name.0, name.1 and so on when its value is too long. The
// value of the first chunk starts with the number of chunks and a dot, so chunks left by a previous longer value are
// ignored.
type cookieSpec struct {
	name     string
	purpose  string
	domain   string
	scope    string
	sameSite http.SameSite
}

// sessionCookie is the session cookie of a [Frontend]. It is only sent on same-site requests.
var sessionCookie = cookieSpec{name: frontendCookie, purpose: "session", sameSite: http.SameSiteStrictMode}

// proxySessionCookie is the session cookie of a [Proxy]. It must be sent on the cross-site navigations to the
// upstream, such as a link from another site or the redirect from the callback after the login, hence the lax mode.
var proxySessionCookie = cookieSpec{name: proxyCookie, purpose: "session", sameSite: http.SameSiteLaxMode}

// loginCookie contains the state of one login flow, for the session cookie. It must be sent on the cross-site
// navigation from the provider to the callback, hence the lax mode.
func loginCookie(session cookieSpec, id string) cookieSpec {
	return cookieSpec{name: session.name + "-Login-" + id, purpose: "login", domain: session.domain, scope: session.scope, sameSite: http.SameSiteLaxMode}
}

func (s cookieSpec) associatedData() []byte {
	return []byte(s.purpose + "\x00" + s.name + "\x00" + s.scope)
}

// write seals the plaintext and adds the chunks to h. A maxAge of 0 makes a browser session cookie. It deletes the
// chunks among cookies that the new value no longer needs.
func (s cookieSpec) write(h http.Header, aead AEAD, plaintext []byte, maxAge int, cookies []*http.Cookie) error {
	ciphertext, err := aead.Encrypt(plaintext, s.associatedData())
	if err != nil {
		return err
	}
	value := base64.RawURLEncoding.EncodeToString(ciphertext)
	// Each chunk leaves room for the count prefix of the first one.
	size := maxChunkSize - 8
	n := (len(value) + size - 1) / size
	for i := range n {
		chunk := value[i*size : min(len(value), (i+1)*size)]
		if i == 0 {
			chunk = strconv.Itoa(n) + "." + chunk
		}
		h.Add("Set-Cookie", s.cookie(i, chunk, maxAge))
	}
	for _, i := range s.sent(cookies) {
		if i >= n {
			h.Add("Set-Cookie", s.cookie(i, "", -1))
		}
	}
	return nil
}

// clear deletes the chunks among cookies and returns their number.
func (s cookieSpec) clear(h http.Header, cookies []*http.Cookie) int {
	sent := s.sent(cookies)
	for _, i := range sent {
		h.Add("Set-Cookie", s.cookie(i, "", -1))
	}
	return len(sent)
}

// sent returns the indexes of the chunks among cookies, each one once.
func (s cookieSpec) sent(cookies []*http.Cookie) []int {
	var sent []int
	prefix := s.name + "."
	for _, c := range cookies {
		if suffix, ok := strings.CutPrefix(c.Name, prefix); ok {
			if i, ok := chunkIndex(suffix); ok {
				sent = append(sent, i)
			}
		}
	}
	slices.Sort(sent)
	return slices.Compact(sent)
}

// read reassembles and opens the chunks among cookies.
func (s cookieSpec) read(cookies []*http.Cookie, aead AEAD) ([]byte, error) {
	var chunks []string
	prefix := s.name + "."
	for _, c := range cookies {
		suffix, ok := strings.CutPrefix(c.Name, prefix)
		if !ok {
			continue
		}
		i, ok := chunkIndex(suffix)
		if !ok || i >= len(cookies) {
			return nil, errInvalidCookie
		}
		if i >= len(chunks) {
			chunks = append(chunks, make([]string, i+1-len(chunks))...)
		}
		if chunks[i] != "" || c.Value == "" {
			return nil, errInvalidCookie
		}
		chunks[i] = c.Value
	}
	if len(chunks) == 0 {
		return nil, errNoCookie
	}

	count, first, ok := strings.Cut(chunks[0], ".")
	n, valid := chunkIndex(count)
	if !ok || !valid || n == 0 || n > len(chunks) {
		return nil, errInvalidCookie
	}
	parts := append([]string{first}, chunks[1:n]...)
	if slices.Contains(parts, "") {
		return nil, errInvalidCookie
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(strings.Join(parts, ""))
	if err != nil {
		return nil, errInvalidCookie
	}
	plaintext, err := aead.Decrypt(ciphertext, s.associatedData())
	if err != nil {
		return nil, errInvalidCookie
	}
	return plaintext, nil
}

func (s cookieSpec) cookie(i int, value string, maxAge int) string {
	c := http.Cookie{ //nolint:gosec // false positive, SameSite is set from the spec (Strict or Lax)
		Name:     s.name + "." + strconv.Itoa(i),
		Value:    value,
		Path:     "/",
		Domain:   s.domain,
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: s.sameSite,
	}
	return c.String()
}

// chunkIndex parses a decimal index of at most 6 digits, without sign or leading zero.
func chunkIndex(s string) (int, bool) {
	if s == "" || len(s) > 6 || len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	n := 0
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}
