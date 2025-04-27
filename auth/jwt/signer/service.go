package signer

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	sjwt "github.com/viant/scy/auth/jwt"
	"sync"

	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/scy"
	jwt2 "github.com/viant/scy/auth/jwt"
	"time"
)

type TokenOption func(token *jwt.Token)

type Service struct {
	config     *Config
	key        []byte
	privateKey *rsa.PrivateKey
	sync.RWMutex
	kid  string
	hmac []byte
}

func (s *Service) Create(ttl time.Duration, content interface{}, options ...TokenOption) (string, error) {
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
		privateKey, err := s.getPrivateKey()
		if err != nil {
			return "", err
		}
		key = privateKey
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
	token := jwt.NewWithClaims(signingMethod, claims)
	if s.kid != "" {
		token.Header["kid"] = s.kid
	}
	for _, option := range options {
		option(token)
	}
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}
	return signed, nil
}

func (s *Service) getPrivateKey() (*rsa.PrivateKey, error) {

	s.RLock()
	privateKey := s.privateKey
	s.RUnlock()

	if privateKey != nil {
		return privateKey, nil
	}
	s.Lock()
	defer s.Unlock()
	if s.privateKey != nil {
		return s.privateKey, nil
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(s.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %w", err)
	}
	pub := &privateKey.PublicKey
	s.kid, err = sjwt.GenerateKid(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to create kid: %w", err)
	}
	return privateKey, nil
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
