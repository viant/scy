package signer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/viant/scy"
	jwt2 "github.com/viant/scy/auth/jwt"
	"time"
)

type Service struct {
	config *Config
	key    []byte
	hmac   []byte
}

func (s Service) Create(ttl time.Duration, content interface{}) (string, error) {
	now := time.Now().UTC()
	claims := &jwt2.Claims{}
	if content != nil {
		if data, _ := json.Marshal(content); len(data) > 0 {
			_ = json.Unmarshal(data, claims)
		}
	}
	var err error
	var key interface{}
	if len(s.key) > 0 {
		key, err = jwt.ParseRSAPrivateKeyFromPEM(s.key)
		if err != nil {
			return "", fmt.Errorf("failed to create key: %w", err)
		}
	}
	claims.Data = content
	claims.ExpiresAt = &jwt.NumericDate{now.Add(ttl)}
	claims.IssuedAt = &jwt.NumericDate{now}
	claims.NotBefore = &jwt.NumericDate{now}

	var signingMethod jwt.SigningMethod = jwt.SigningMethodRS256
	if len(s.hmac) > 0 {
		signingMethod = jwt.SigningMethodHS512
		key = s.hmac
	}
	token, err := jwt.NewWithClaims(signingMethod, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}
	return token, nil
}

func (s *Service) Init(ctx context.Context) error {
	if s.config.RSA != nil {
		scySrv := scy.New()
		secret, err := scySrv.Load(ctx, s.config.RSA)
		if err != nil {
			return err
		}
		s.key = []byte(secret.String())
	}
	if s.config.HMAC != nil {
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
	return &Service{
		config: config,
	}
}
