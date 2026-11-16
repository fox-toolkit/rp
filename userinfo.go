// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"golang.org/x/oauth2"
)

const maxUserInfoSize = 1 << 20

var errNoUserInfoEndpoint = errors.New("no userinfo endpoint")

// requestUserInfo returns the subject and the claims of the UserInfo response (OpenID Connect Core 5.3). A signed
// response is verified with the provider keys, like the ID tokens.
func (rp *relyingParty) requestUserInfo(ctx context.Context, client *http.Client, token *oauth2.Token) (string, json.RawMessage, error) {
	endpoint := rp.provider.oidc.UserInfoEndpoint()
	if endpoint == "" {
		return "", nil, errNoUserInfoEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", nil, err
	}
	token.SetAuthHeader(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUserInfoSize))
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("userinfo endpoint: status %d", resp.StatusCode)
	}
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil && mediaType == "application/jwt" {
		if body, err = (providerKeySet{rp.provider.keys}).VerifySignature(ctx, string(body)); err != nil {
			return "", nil, fmt.Errorf("signed userinfo: %w", err)
		}
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return "", nil, err
	}
	return claims.Subject, body, nil
}
