package custom

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/viant/scy/auth"
	"github.com/viant/scy/auth/jwt/signer"
	"io"
	"time"
)

// Service represents a custom auth service
type Service struct {
	config            *Config
	jwtSigner         *signer.Service
	authConnector     Connector
	identityConnector Connector
}

// Authenticate authenticates user
func (s *Service) Authenticate(ctx context.Context, id, password string, expireIn time.Duration, claims string) (*auth.Token, error) {
	err := s.config.EnsureSQL()
	if err != nil {
		return nil, err
	}
	ret, err := s.authenticate(ctx, id, password, expireIn, claims)
	if err != nil {
		return nil, newAuthError(err)
	}
	return ret, nil
}

// SetPassword sets password
func (s *Service) SetPassword(ctx context.Context, id, password string) error {
	err := s.config.EnsureSQL()
	if err != nil {
		return err
	}
	aSubject, err := s.fetchSubject(ctx, id)
	if err != nil {
		if err == io.EOF {
			err = nil
		}
		if err != nil {
			return err
		}
	}
	isInsert := aSubject == nil
	db, err := s.authConnector.DB()
	if err != nil {
		return err
	}

	hashedPassword, err := HashPassword(password)
	if err != nil {
		return err
	}
	if isInsert {
		_, err = db.ExecContext(ctx, s.config.insertSQL, id, hashedPassword)
	} else {
		_, err = db.ExecContext(ctx, s.config.updateSQL, hashedPassword, id)
	}
	return err
}

func (s *Service) authenticate(ctx context.Context, id string, password string, expireIn time.Duration, claims string) (*auth.Token, error) {
	if s.jwtSigner == nil {
		return nil, fmt.Errorf("jwtSigner was nil")
	}
	if s.config.IdentitySQL != "" {
		identity, err := s.fetchIdentity(ctx, id)
		if err != nil {
			return nil, err
		}
		if identity == nil {
			return nil, fmt.Errorf("invalid identity: %v", id)
		}
		id = identity.ID
	}
	subject, err := s.fetchSubject(ctx, id)
	if err != nil {
		return nil, err
	}
	if subject == nil {
		return nil, fmt.Errorf("invalid subject: %v", id)
	}
	if subject.IsLocked(s.config.MaxAttempts) {
		return nil, fmt.Errorf("account is locked")
	}
	if !CheckPasswordHash(password, *subject.Password) {
		if err = s.increaseAttempts(ctx, id); err != nil {
			return nil, fmt.Errorf("invalid password %v", err)
		}
		return nil, fmt.Errorf("invalid password")
	}

	updatedClaims, err := s.updateClaim(claims, id)
	if err != nil {
		return nil, err
	}
	if expireIn == 0 {
		expireIn = time.Hour
	}
	expiry := time.Now().Add(expireIn)
	token, err := s.jwtSigner.Create(expireIn, updatedClaims)
	if err != nil {
		return nil, err
	}
	ret := &auth.Token{
		IDToken: token,
	}
	ret.Expiry = expiry
	return ret, nil
}

func (s *Service) increaseAttempts(ctx context.Context, id string) error {
	if s.config.attempsSQL == "" {
		return nil
	}
	db, err := s.authConnector.DB()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, s.config.attempsSQL, 1, id)
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) fetchIdentity(ctx context.Context, id string) (*Identity, error) {
	db, err := s.identityConnector.DB()
	if err != nil {
		return nil, err
	}
	identity := &Identity{}
	row := db.QueryRowContext(ctx, s.config.IdentitySQL, id)
	if err = row.Scan(&identity.ID); err != nil {
		return nil, handlerQueryError(err)
	}
	if err = row.Err(); err != nil {
		return nil, err
	}
	if identity.ID == "" {
		return nil, nil
	}
	return identity, nil
}

func (s *Service) fetchSubject(ctx context.Context, id string) (*Subject, error) {
	db, err := s.authConnector.DB()
	if err != nil {
		return nil, err
	}
	subject := &Subject{}
	row := db.QueryRowContext(ctx, s.config.AuthSQL, id)
	if err = row.Scan(&subject.Password, &subject.Locked, &subject.Attempts); err != nil {
		return nil, handlerQueryError(err)
	}

	if err = row.Err(); err != nil {
		return nil, err
	}
	if subject.Password == nil {
		return nil, fmt.Errorf("password was empty")
	}
	return subject, nil
}

func handlerQueryError(err error) error {
	if err == nil || err == sql.ErrNoRows || err == io.EOF {
		return nil
	}
	return err
}

func (s *Service) updateClaim(claims string, id string) (string, error) {
	var claimsMap map[string]interface{}
	if claims != "" {
		err := json.Unmarshal([]byte(claims), &claimsMap)
		if err != nil {
			return "", err
		}
	}
	claimsMap["sub"] = id
	data, err := json.Marshal(claimsMap)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func New(config *Config, authConnector, identityConnector Connector, signer *signer.Service) *Service {
	return &Service{config: config, authConnector: authConnector, identityConnector: identityConnector, jwtSigner: signer}
}
