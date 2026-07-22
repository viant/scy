package signer

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/scy"
	jwt2 "github.com/viant/scy/auth/jwt"
	sjwt "github.com/viant/scy/auth/jwt"
	"strings"
	"sync"
	"time"
)

type TokenOption func(token *jwt.Token)

type profile struct {
	resources  []string
	algorithm  string
	compact    bool
	key        []byte
	privateKey *rsa.PrivateKey
	kid        string
	hmac       []byte
	sync.RWMutex
}

type Service struct {
	config         *Config
	defaultProfile *profile
	rules          []*profile
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

	if shouldEmbedContent(content) {
		claims.Data = content
	}
	selected := s.selectProfile([]string(claims.Audience))
	if selected == nil {
		return "", fmt.Errorf("create: no jwt signing profile configured for audience %v", []string(claims.Audience))
	}
	applyStandardTimes(claims, now, ttl, selected.compact)
	signingMethod, err := selected.signingMethod()
	if err != nil {
		return "", err
	}
	key, kid, err := selected.signingKey()
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(signingMethod, claims)
	if kid != "" {
		token.Header["kid"] = kid
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

func (p *profile) signingMethod() (jwt.SigningMethod, error) {
	algorithm := strings.ToUpper(strings.TrimSpace(p.algorithm))
	if algorithm == "" {
		if len(p.hmac) > 0 {
			return jwt.SigningMethodHS512, nil
		}
		return jwt.SigningMethodRS256, nil
	}
	method := jwt.GetSigningMethod(algorithm)
	if method == nil {
		return nil, fmt.Errorf("create: unsupported signing algorithm %q", p.algorithm)
	}
	if len(p.hmac) > 0 {
		if _, ok := method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("create: algorithm %q requires HMAC key", p.algorithm)
		}
		return method, nil
	}
	if _, ok := method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("create: algorithm %q requires RSA key", p.algorithm)
	}
	return method, nil
}

func (p *profile) signingKey() (interface{}, string, error) {
	if len(p.hmac) > 0 {
		return p.hmac, "", nil
	}
	privateKey, err := p.getPrivateKey()
	if err != nil {
		return nil, "", err
	}
	return privateKey, p.kid, nil
}

func (p *profile) getPrivateKey() (*rsa.PrivateKey, error) {
	p.RLock()
	privateKey := p.privateKey
	p.RUnlock()
	if privateKey != nil {
		return privateKey, nil
	}
	p.Lock()
	defer p.Unlock()
	if p.privateKey != nil {
		return p.privateKey, nil
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(p.key)
	if err != nil {
		return nil, fmt.Errorf("create: failed to parse private key: %w", err)
	}
	pub := &privateKey.PublicKey
	p.kid, err = sjwt.GenerateKid(pub)
	if err != nil {
		return nil, fmt.Errorf("create: failed to create kid: %w", err)
	}
	p.privateKey = privateKey
	return privateKey, nil
}

func (p *profile) init(ctx context.Context, rsaResource, hmacResource *scy.Resource) error {
	if rsaResource != nil && hmacResource != nil {
		return fmt.Errorf("create: both RSA and HMAC were configured for one signing profile")
	}
	if rsaResource == nil && hmacResource == nil {
		return fmt.Errorf("create: signing profile was missing RSA or HMAC key")
	}
	if rsaResource != nil {
		scySrv := scy.New()
		secret, err := scySrv.Load(ctx, rsaResource)
		if err != nil {
			return err
		}
		p.key = []byte(secret.String())
	}
	if hmacResource != nil {
		scySrv := scy.New()
		secret, err := scySrv.Load(ctx, hmacResource)
		if err != nil {
			return err
		}
		if p.hmac, err = base64.StdEncoding.DecodeString(secret.String()); err != nil {
			p.hmac = []byte(secret.String())
		}
	}
	return nil
}

func (p *profile) matches(audience []string) bool {
	if len(p.resources) == 0 {
		return true
	}
	if len(audience) == 0 {
		return false
	}
	for _, candidate := range audience {
		for _, resource := range p.resources {
			if candidate == resource {
				return true
			}
		}
	}
	return false
}

func (s *Service) selectProfile(audience []string) *profile {
	for _, candidate := range s.rules {
		if candidate.matches(audience) {
			return candidate
		}
	}
	return s.defaultProfile
}

func (s *Service) Init(ctx context.Context) error {
	if s.config == nil {
		return nil
	}
	if s.config.RSA != nil || s.config.HMAC != nil {
		s.defaultProfile = &profile{compact: s.config.Compact}
		if err := s.defaultProfile.init(ctx, s.config.RSA, s.config.HMAC); err != nil {
			return err
		}
	}
	for _, rule := range s.config.Rules {
		if rule == nil {
			continue
		}
		candidate := &profile{
			resources: append([]string{}, rule.Resource...),
			algorithm: rule.Algorithm,
			compact:   rule.Compact,
		}
		if err := candidate.init(ctx, rule.RSA, rule.HMAC); err != nil {
			return err
		}
		s.rules = append(s.rules, candidate)
	}
	return nil
}

func New(config *Config) *Service {
	return &Service{
		config: config,
	}
}

func shouldEmbedContent(content interface{}) bool {
	switch content.(type) {
	case nil:
		return false
	case jwt2.Claims, *jwt2.Claims:
		return false
	default:
		return true
	}
}

func applyStandardTimes(claims *jwt2.Claims, now time.Time, ttl time.Duration, compact bool) {
	if claims == nil {
		return
	}
	claims.ExpiresAt = &jwt.NumericDate{now.Add(ttl)}
	if compact {
		claims.IssuedAt = nil
		claims.NotBefore = nil
		return
	}
	claims.IssuedAt = &jwt.NumericDate{now}
	claims.NotBefore = &jwt.NumericDate{now}
}
