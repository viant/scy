package flow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func fetchCodeFromLocationHeader(response *http.Response) (string, error) {
	if response.StatusCode/100 != 3 {
		return "", fmt.Errorf("unexpected status %d", response.StatusCode)
	}
	loc := response.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		return "", fmt.Errorf("bad redirect URI: %w", err)
	}
	if msg := u.Query().Get("error"); msg != "" {
		return "", fmt.Errorf("authorization error: %s", msg)
	}
	code := u.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("missing code in redirect")
	}
	return code, nil
}

func buildAuthCodeURL(redirectURL string, config *oauth2.Config, opts *Options) (string, error) {
	var oauth2Options = []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("redirect_uri", redirectURL),
	}
	// Add PKCE parameters only if PKCE is enabled
	if opts.usePKCE {
		codeVerifier, err := opts.CodeVerifier()
		if err != nil {
			return "", err
		}
		oauth2Options = append(oauth2Options,
			oauth2.SetAuthURLParam("code_challenge", generateCodeChallenge(codeVerifier)),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}
	scopes := opts.Scopes(config.Scopes...)
	oauth2Options = append(oauth2Options, oauth2.SetAuthURLParam("scope", strings.Join(scopes, " ")))

	for paramName, paramValue := range opts.authURLParams {
		oauth2Options = append(oauth2Options, oauth2.SetAuthURLParam(paramName, paramValue))
	}
	URL := config.AuthCodeURL(opts.State(), oauth2Options...)
	return URL, nil
}

// generateCodeChallenge creates a PKCE code challenge from a code verifier
func generateCodeChallenge(verifier string) string {
	sha := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sha[:])
}

// randomToken generates a cryptographically secure random token
func randomToken() string {
	const nBytes = 32

	buf := make([]byte, nBytes)

	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		// Fallback (should almost never happen).
		rnd := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
		for i := range buf {
			buf[i] = byte(rnd.Intn(256))
		}
	}

	return base64.RawURLEncoding.EncodeToString(buf)
}

// postFormData  x-www-form-urlencoded POST
func postFormData(URL string, data map[string]string) (*http.Response, error) {
	form := url.Values{}
	for k, v := range data {
		form.Set(k, v)
	}
	req, err := http.NewRequest("POST", URL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// returning this prevents redirects
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
			fmt.Println(string(data))
		}
		resp.Body.Close()
	}
	return resp, nil
}
