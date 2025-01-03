package firebase

import (
	"bytes"
	"context"
	"encoding/json"
	firebase "firebase.google.com/go/v4"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/viant/scy"
	sauth "github.com/viant/scy/auth"
	sjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/cred"
	"golang.org/x/oauth2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/identitytoolkit/v3"
	"google.golang.org/api/option"
	"io"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"time"
)

type Service struct {
	options   []option.ClientOption
	identity  *identitytoolkit.Service
	app       *firebase.App
	config    *Config
	webAPIKey string
}

func (s *Service) InitiateBasicAuth(ctx context.Context, username, password string) (*sauth.Token, error) {
	req := &identitytoolkit.IdentitytoolkitRelyingpartyVerifyPasswordRequest{
		Email:             username,
		Password:          password,
		ReturnSecureToken: true,
	}
	resp, err := s.identity.Relyingparty.VerifyPassword(req).Context(ctx).Do()
	if err != nil {
		// Check for specific Firebase error codes or messages
		if apiError, ok := err.(*googleapi.Error); ok {
			switch apiError.Code {
			case http.StatusBadRequest:
				if apiError.Message == "USER_DISABLED" {
					return nil, fmt.Errorf("account is disabled")
				}
				if apiError.Message == "RESET_PASSWORD_REQUIRED" {
					return nil, sauth.NewChallengeError(sauth.NewPasswordRequired)
				}
			}
		}
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

func (s *Service) ensureApiKey(ctx context.Context) error {
	if s.config == nil || s.config.WebAPIKey == nil {
		return fmt.Errorf("missing Firebase Web API key in config")
	}
	if s.webAPIKey != "" {
		return nil
	}
	secretService := scy.New()
	s.config.WebAPIKey.SetTarget(reflect.TypeOf(cred.Generic{}))
	// Decode the scy resource
	secret, err := secretService.Load(ctx, s.config.WebAPIKey)
	if err != nil {
		return fmt.Errorf("failed to load Web API key secret: %w", err)
	}
	genericCred, ok := secret.Target.(*cred.Generic)
	if !ok {
		return fmt.Errorf("invalid Web API key secret type: %T", secret.Target)
	}
	// Read the secret into apiKey
	if genericCred.SecretKey.Secret == "" {
		return fmt.Errorf("secret key is empty")
	}
	s.webAPIKey = genericCred.SecretKey.Secret
	return nil
}

// ReissueIdentityToken obtains a fresh ID token by calling the Secure Token API
// with a valid refresh token.
func (s *Service) ReissueIdentityToken(ctx context.Context, refreshToken string, subject string) (*sauth.Token, error) {
	// Retrieve your Firebase Web API key from s.config
	if s.config == nil || s.config.WebAPIKey == nil {
		return nil, fmt.Errorf("missing Firebase Web API key in config")
	}
	if err := s.ensureApiKey(ctx); err != nil {
		return nil, err
	}
	apiKey := s.webAPIKey
	// Build the Secure Token API URL
	url := fmt.Sprintf("https://securetoken.googleapis.com/v1/token?key=%s", apiKey)

	// Build the request payload
	payload := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal refresh payload: %w", err)
	}

	// Create the POST request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call secure token API: %w", err)
	}
	defer resp.Body.Close()

	// Handle non-200 responses
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("secure token API returned status %d: %s", resp.StatusCode, string(data))
	}

	// Parse the Secure Token API response
	var tokenRes struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    string `json:"expires_in"`
		TokenType    string `json:"token_type"`
		AccessToken  string `json:"access_token,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		return nil, fmt.Errorf("failed to decode refresh token response: %w", err)
	}

	// Convert expires_in to an integer
	expiresSec, err := strconv.Atoi(tokenRes.ExpiresIn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_in: %w", err)
	}

	// Calculate new expiry
	expiry := time.Now().Add(time.Duration(expiresSec) * time.Second)

	// Return our custom Token, reusing oauth2.Token
	return &sauth.Token{
		Token: oauth2.Token{
			AccessToken:  tokenRes.AccessToken,  // May be empty if not provided
			TokenType:    tokenRes.TokenType,    // Often "Bearer"
			RefreshToken: tokenRes.RefreshToken, // May be same or new
			Expiry:       expiry,
		},
		IDToken: tokenRes.IDToken,
	}, nil
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

func (s *Service) ResetCredentials(ctx context.Context, email, newPassword string) error {
	req := &identitytoolkit.IdentitytoolkitRelyingpartySetAccountInfoRequest{
		Email:    email,
		Password: newPassword,
	}
	if _, err := s.identity.Relyingparty.SetAccountInfo(req).Context(ctx).Do(); err != nil {
		return fmt.Errorf("failed to reset credentials for %s: %w", email, err)
	}
	return nil
}

func New(ctx context.Context, config *Config, options ...option.ClientOption) (*Service, error) {
	if config.Config == nil {
		config.Config = &firebase.Config{}
	}

	if config.Secrets != nil {
		secretService := scy.New()
		config.Secrets.SetTarget(reflect.TypeOf(cred.Generic{}))
		// Decode the scy resource
		secret, err := secretService.Load(ctx, config.Secrets)
		if err != nil {
			return nil, err
		}
		if config.Config == nil {
			config.Config = &firebase.Config{}
		}
		generic := secret.Target.(*cred.Generic)
		options = append(options, option.WithCredentialsJSON([]byte(secret.String())))
		config.ServiceAccountID = generic.JwtConfig.ClientEmail
		config.Config.ProjectID = generic.JwtConfig.ProjectID
	}
	app, err := firebase.NewApp(ctx, config.Config, options...)
	if err != nil {
		return nil, err
	}
	identity, err := identitytoolkit.NewService(ctx, options...)
	if err != nil {
		return nil, err
	}
	return &Service{
		config:   config,
		options:  options,
		app:      app,
		identity: identity,
	}, nil
}
