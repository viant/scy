package verifier

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/scy"
	sjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/cache"
	"strings"
)

type profile struct {
	resources  []string
	algorithm  string
	keys       [][]byte
	hmac       []byte
	publicKeys map[string]*rsa.PublicKey
}

type Service struct {
	defaultProfile *profile
	rules          []*profile
	cache          *cache.Cache
	config         *Config
}

// PublicKeys returns RSA public keys from the default verification profile.
// This preserves the pre-rules behavior used by JWKS endpoints.
func (s *Service) PublicKeys() (map[string]*rsa.PublicKey, error) {
	if s.defaultProfile == nil || len(s.defaultProfile.publicKeys) == 0 {
		return map[string]*rsa.PublicKey{}, nil
	}
	result := make(map[string]*rsa.PublicKey, len(s.defaultProfile.publicKeys))
	for kid, key := range s.defaultProfile.publicKeys {
		result[kid] = key
	}
	return result, nil
}

// Validate checks if  jwt token is valid
func (s *Service) Validate(ctx context.Context, tokenString string) (*jwt.Token, error) {
	if s.config == nil {
		return nil, fmt.Errorf("jwt verifier config was empty")
	}
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

func (p *profile) hasRSA() bool {
	return len(p.publicKeys) > 0
}

func (p *profile) hasHMAC() bool {
	return len(p.hmac) > 0
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

func (p *profile) supportsAlg(alg string) bool {
	if alg == "" {
		return false
	}
	alg = strings.ToUpper(strings.TrimSpace(alg))
	if p.algorithm != "" {
		return strings.EqualFold(p.algorithm, alg)
	}
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return false
	}
	if p.hasRSA() {
		_, ok := method.(*jwt.SigningMethodRSA)
		return ok
	}
	if p.hasHMAC() {
		_, ok := method.(*jwt.SigningMethodHMAC)
		return ok
	}
	return false
}

func (p *profile) keyForToken(token *jwt.Token) (interface{}, error) {
	if !p.supportsAlg(token.Method.Alg()) {
		return nil, fmt.Errorf("unexpected method: %T %s", token.Method, token.Header["alg"])
	}
	if p.hasHMAC() {
		return p.hmac, nil
	}
	if len(p.publicKeys) == 1 {
		for _, candidate := range p.publicKeys {
			return candidate, nil
		}
	}
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("kid header not found")
	}
	key, ok := p.publicKeys[kid]
	if ok {
		return key, nil
	}
	return nil, fmt.Errorf("key %v not found", kid)
}

func (s *Service) validateWithPublicKey(tokenString string) (*jwt.Token, error) {
	selected, err := s.selectProfile(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	token, err := jwt.Parse(tokenString, func(jwtToken *jwt.Token) (interface{}, error) {
		return selected.keyForToken(jwtToken)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	return token, nil
}

func (p *profile) init(ctx context.Context, rsaResources []*scy.Resource, hmacResource *scy.Resource) error {
	if len(rsaResources) > 0 && hmacResource != nil {
		return fmt.Errorf("both RSA and HMAC were configured for one verification profile")
	}
	if len(rsaResources) == 0 && hmacResource == nil {
		return fmt.Errorf("verification profile was missing RSA or HMAC key")
	}
	scySrv := scy.New()
	for _, resource := range rsaResources {
		secret, err := scySrv.Load(ctx, resource)
		if err != nil {
			return err
		}
		p.keys = append(p.keys, []byte(secret.String()))
	}
	if hmacResource != nil && hmacResource.URL != "" {
		secret, err := scySrv.Load(ctx, hmacResource)
		if err != nil {
			return err
		}
		if p.hmac, err = base64.StdEncoding.DecodeString(secret.String()); err != nil {
			p.hmac = []byte(secret.String())
		}
	}
	if len(p.keys) > 0 {
		p.publicKeys = make(map[string]*rsa.PublicKey, len(p.keys))
		for _, key := range p.keys {
			publicKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
			if err != nil {
				return fmt.Errorf("failed to parse public key: %w", err)
			}
			kid, err := sjwt.GenerateKid(publicKey)
			if err != nil {
				return fmt.Errorf("failed to generate kid: %w", err)
			}
			p.publicKeys[kid] = publicKey
		}
	}
	return nil
}

func (s *Service) validateWithCert(ctx context.Context, tokenString string) (*jwt.Token, error) {
	keySet, err := s.cache.Fetch(ctx, s.config.CertURL)
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		keys, ok := keySet.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("keys %v not found", kid)
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

func (s *Service) selectProfile(tokenString string) (*profile, error) {
	unsafeToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims, err := sjwt.NewClaim(unsafeToken)
	if err != nil {
		return nil, err
	}
	alg, _ := unsafeToken.Header["alg"].(string)
	var scoped []*profile
	for _, candidate := range s.rules {
		if candidate.matches([]string(claims.Audience)) {
			scoped = append(scoped, candidate)
		}
	}
	if len(scoped) > 0 {
		for _, candidate := range scoped {
			if candidate.supportsAlg(alg) {
				return candidate, nil
			}
		}
		return nil, fmt.Errorf("no jwt verification profile matched audience %v and algorithm %q", []string(claims.Audience), alg)
	}
	if s.defaultProfile != nil && s.defaultProfile.supportsAlg(alg) {
		return s.defaultProfile, nil
	}
	return nil, fmt.Errorf("no jwt verification profile matched algorithm %q", alg)
}

func (s *Service) Init(ctx context.Context) error {
	if s.config == nil {
		return nil
	}
	if len(s.config.RSA) > 0 || s.config.HMAC != nil {
		s.defaultProfile = &profile{}
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
		}
		if err := candidate.init(ctx, rule.RSA, rule.HMAC); err != nil {
			return err
		}
		s.rules = append(s.rules, candidate)
	}
	return nil
}

func New(config *Config) *Service {
	return &Service{config: config, cache: cache.New()}
}
