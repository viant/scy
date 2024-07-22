package custom

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
func (s *Service) Authenticate(ctx context.Context, id, password string, expireIn time.Duration, claims string) (string, error) {
	err := s.config.EnsureSQL()
	if err != nil {
		return "", err
	}
	ret, err := s.authenticate(ctx, id, password, expireIn, claims)
	if err != nil {
		return "", newAuthError(err)
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

func (s *Service) authenticate(ctx context.Context, id string, password string, expireIn time.Duration, claims string) (string, error) {
	if s.config.IdentitySQL == "" {
		identity, err := s.fetchIdentity(ctx, id)
		if err != nil {
			return "", err
		}
		id = identity.ID
	}
	subject, err := s.fetchSubject(ctx, id)
	if err != nil {
		return "", err
	}
	if subject == nil {
		return "", fmt.Errorf("invalid subject: %v", id)
	}
	if subject.IsLocked(s.config.MaxAttempts) {
		return "", fmt.Errorf("account is locked")
	}
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	if !CheckPasswordHash(password, hashedPassword) {
		return "", fmt.Errorf("invalid password")
	}
	updatedClaims, err := s.updateClaim(claims, subject)
	if err != nil {
		return "", err
	}
	if expireIn == 0 {
		expireIn = time.Hour
	}
	return s.jwtSigner.Create(expireIn, updatedClaims)
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
	db, err := s.identityConnector.DB()
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
		return nil, nil
	}
	return subject, nil
}

func handlerQueryError(err error) error {
	if err == nil || err == sql.ErrNoRows || err == io.EOF {
		return nil
	}
	return err
}

func (s *Service) updateClaim(claims string, subject *Subject) (string, error) {
	var claimsMap map[string]interface{}
	if claims != "" {
		err := json.Unmarshal([]byte(claims), &claimsMap)
		if err != nil {
			return "", err
		}
	}
	claimsMap["sub"] = subject.ID
	data, err := json.Marshal(claimsMap)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func New(config *Config, authConnector, identityConnector Connector, signer *signer.Service) *Service {
	return &Service{config: config, authConnector: authConnector, identityConnector: identityConnector, jwtSigner: signer}
}
