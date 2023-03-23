package verifier

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/viant/scy"
	sjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/cache"
)

type Service struct {
	key    []byte
	hmac   []byte
	cache  *cache.Cache
	config *Config
}

//Validate checks if  jwt token is valid
func (s *Service) Validate(ctx context.Context, tokenString string) (*jwt.Token, error) {
	if s.config.CertURL != "" {
		return s.validateWithCert(ctx, tokenString)
	}
	return s.validateWithPublicKey(tokenString)
}

func (s *Service) VerifyClaims(ctx context.Context, tokenString string) (*sjwt.Claims, error) {
	token, err := s.Validate(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	return sjwt.NewClaim(token)
}

func (s *Service) ValidaToken(ctx context.Context, tokenString string) (*jwt.Token, error) {
	token, err := s.Validate(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (s *Service) validateWithPublicKey(tokenString string) (*jwt.Token, error) {

	token, err := jwt.Parse(tokenString, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); ok {
			return jwt.ParseRSAPublicKeyFromPEM(s.key)
		}
		if _, ok := jwtToken.Method.(*jwt.SigningMethodHMAC); ok {
			return s.hmac, nil
		}
		return nil, fmt.Errorf("unexpected method: %T %s ", jwtToken.Method, jwtToken.Header["alg"])
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	return token, nil
}

func (s *Service) validateWithCert(ctx context.Context, tokenString string) (*jwt.Token, error) {
	keySet, err := s.cache.Fetch(ctx, s.config.CertURL)
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}
		keys, ok := keySet.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("key %v not found", kid)
		}
		var publicKey interface{}
		err = keys.Raw(&publicKey)
		if err != nil {
			return nil, fmt.Errorf("could not parse pubkey")
		}
		return publicKey, nil
	})
	return token, err
}

func (s *Service) Init(ctx context.Context) error {
	if s.config.RSA != nil && s.config.RSA.URL != "" {
		scySrv := scy.New()
		secret, err := scySrv.Load(ctx, s.config.RSA)
		if err != nil {
			return err
		}
		s.key = []byte(secret.String())
	}
	if s.config.HMAC != nil && s.config.HMAC.URL != "" {
		scySrv := scy.New()
		secret, err := scySrv.Load(ctx, s.config.HMAC)
		if err != nil {
			return err
		}
		if s.hmac, err = base64.StdEncoding.DecodeString(secret.String()); err != nil {
			s.hmac = []byte(secret.String())
		}
	}
	return nil
}

func New(config *Config) *Service {
	return &Service{config: config, cache: cache.New()}
}
