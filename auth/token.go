package auth

import (
	"fmt"
	"golang.org/x/oauth2"
	"reflect"
	"time"
	"unsafe"
)

type Token struct {
	oauth2.Token
	IDToken string `json:"id_token,omitempty"`
}

// Expired returns true if expired
func (t Token) Expired(now time.Time) bool {
	return t.Expiry.Before(now)
}

func (t *Token) IdentityToken() (*oauth2.Token, error) {
	if t.IDToken == "" {
		return nil, fmt.Errorf("invalid identity token")
	}
	return &oauth2.Token{
		AccessToken:  t.IDToken,
		TokenType:    t.TokenType,
		RefreshToken: t.RefreshToken,
		Expiry:       t.Expiry,
	}, nil
}

func (t *Token) PopulateIDToken() {
	raw := t.Raw()
	if raw == nil {
		return
	}
	if rawMap, ok := raw.(map[string]interface{}); ok {
		if token, ok := rawMap["id_token"]; ok {
			t.IDToken = token.(string)
		}
	}
}

func (t *Token) Raw() interface{} {
	ptr := unsafe.Pointer(&t.Token)
	raw := *(*interface{})(unsafe.Pointer(uintptr(ptr) + rawField.Offset))
	return raw
}

func init() {
	rawField, _ = reflect.TypeOf(oauth2.Token{}).FieldByName("raw")
}

var rawField reflect.StructField
