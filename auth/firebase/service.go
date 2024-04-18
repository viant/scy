package firebase

import (
	"context"
	firebase "firebase.google.com/go/v4"
	"github.com/golang-jwt/jwt/v4"
	sauth "github.com/viant/scy/auth"
	sjwt "github.com/viant/scy/auth/jwt"
	"golang.org/x/oauth2"
	"google.golang.org/api/identitytoolkit/v3"
	"google.golang.org/api/option"
	"log"
	"time"
)

type Service struct {
	options  []option.ClientOption
	identity *identitytoolkit.Service
	app      *firebase.App
	config   *firebase.Config
}

func (s *Service) InitiateBasicAuth(ctx context.Context, username, password string) (*sauth.Token, error) {
	req := &identitytoolkit.IdentitytoolkitRelyingpartyVerifyPasswordRequest{
		Email:             username,
		Password:          password,
		ReturnSecureToken: true,
	}
	resp, err := s.identity.Relyingparty.VerifyPassword(req).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	expiredAt := time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	result := &sauth.Token{
		IDToken: resp.IdToken,
		Token: oauth2.Token{
			AccessToken:  resp.OauthAccessToken,
			TokenType:    "Bearer",
			RefreshToken: resp.RefreshToken,
			Expiry:       expiredAt,
		},
	}
	return result, nil
}

func (s *Service) VerifyIdentity(ctx context.Context, rawToken string) (*sjwt.Claims, error) {
	authClient, err := s.app.Auth(context.Background())
	if err != nil {
		log.Fatalf("error getting Auth client: %v", err)
	}
	token, err := authClient.VerifyIDToken(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	expiresAt := jwt.NewNumericDate(time.Unix(token.Expires, 0))
	issuedAt := jwt.NewNumericDate(time.Unix(token.IssuedAt, 0))
	registredClaims := jwt.RegisteredClaims{
		Issuer:    token.Issuer,
		Subject:   token.Subject,
		Audience:  jwt.ClaimStrings{token.Audience},
		ExpiresAt: expiresAt,
		NotBefore: nil,
		IssuedAt:  issuedAt,
		ID:        token.UID,
	}
	result := &sjwt.Claims{
		RegisteredClaims: registredClaims,
		Data:             token.Claims,
	}
	if len(token.Claims) > 0 {
		if value, ok := token.Claims["email"]; ok {
			result.Email = value.(string)
		}
		if value, ok := token.Claims["email_verified"]; ok {
			result.VerifiedEmail = value.(bool)
		}
		if value, ok := token.Claims["email_verified"]; ok {
			result.VerifiedEmail = value.(bool)
		}

	}
	return result, nil
}

func New(ctx context.Context, config *firebase.Config, options ...option.ClientOption) (*Service, error) {
	app, err := firebase.NewApp(ctx, config, options...)
	if err != nil {
		return nil, err
	}
	identity, err := identitytoolkit.NewService(ctx, options...)
	if err != nil {
		return nil, err
	}
	return &Service{
		options:  options,
		app:      app,
		identity: identity,
	}, nil
}
