package cognito

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/viant/scy"
	"github.com/viant/scy/auth"
	sjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/verifier"
	"github.com/viant/scy/cred"
	"reflect"
	"time"
)

type (
	//Service represents cognito client
	Service struct {
		client   *cognitoidentityprovider.CognitoIdentityProvider
		config   *Config
		verifier *verifier.Service
	}
)

func (s *Service) secretHash(username string) string {
	mac := hmac.New(sha256.New, []byte(s.config.Client.Secret)) // Key: ClientSecret
	mac.Write([]byte(username + s.config.Client.Id))            // Message: username + ClientId
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// InitiateBasicAuth initiates basic auth
func (s *Service) InitiateBasicAuth(username, password string) (*auth.Token, error) {
	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String(s.config.AuthFlow),
		AuthParameters: map[string]*string{
			"USERNAME":    aws.String(username),
			"PASSWORD":    aws.String(password),
			"SECRET_HASH": aws.String(s.secretHash(username)),
		},
		ClientId: aws.String(s.config.Client.Id), // this is the app client ID
	}
	output, err := s.client.InitiateAuth(input)
	if err != nil {
		return nil, err
	}
	if output.ChallengeName != nil {
		return nil, auth.NewChallenge(*output.ChallengeName)
	}
	token := &auth.Token{}
	if res := output.AuthenticationResult; res != nil {
		if value := res.AccessToken; value != nil {
			token.AccessToken = *value
		}
		if value := res.TokenType; value != nil {
			token.TokenType = *value
		}
		if value := res.RefreshToken; value != nil {
			token.RefreshToken = *value
		}
		if value := res.ExpiresIn; value != nil {
			token.Expiry = time.Unix(*value, 0)
		}
		if value := res.IdToken; value != nil {
			token.IDToken = *value
		}
	}
	return token, nil
}

// ReissueIdentityToken reissues identity token
func (s *Service) ReissueIdentityToken(ctx context.Context, refreshToken string, subject string) (*auth.Token, error) {
	authParams := map[string]*string{
		"REFRESH_TOKEN": aws.String(refreshToken),
		"USERNAME":      aws.String(subject), //use token subject instead of username
	}
	if s.config.Client.Secret != "" {
		authParams["SECRET_HASH"] = aws.String(s.secretHash(subject))
	}

	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow:       aws.String("REFRESH_TOKEN_AUTH"),
		AuthParameters: authParams,
		ClientId:       aws.String(s.config.Client.Id),
	}

	output, err := s.client.InitiateAuthWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to reissue identity token: %w", err)
	}

	token := &auth.Token{}
	if res := output.AuthenticationResult; res != nil {
		if value := res.AccessToken; value != nil {
			token.AccessToken = *value
		}
		if value := res.TokenType; value != nil {
			token.TokenType = *value
		}
		if value := res.IdToken; value != nil {
			token.IDToken = *value
		}
		if value := res.ExpiresIn; value != nil {
			token.Expiry = time.Now().Add(time.Duration(*value) * time.Second)
		}
	}
	return token, nil
}

// VerifyIdentity verifies identity token, it returns jwt claims
func (s *Service) VerifyIdentity(ctx context.Context, rawToken string) (*sjwt.Claims, error) {
	token, err := s.verifier.Validate(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	claims, err := sjwt.NewClaim(token)
	if err != nil {
		return nil, err
	}
	if !claims.VerifyAudience(s.config.Client.Id, true) {
		return nil, fmt.Errorf("invalid issuer")
	}
	return claims, err
}

// New creates new cogito auth service
func New(ctx context.Context, config *Config) (*Service, error) {
	config.Init()
	if config.Resource != nil {
		secrets := scy.New()
		config.Resource.SetTarget(reflect.TypeOf(config.Client))
		secret, err := secrets.Load(ctx, config.Resource)
		if err != nil {
			return nil, err
		}
		config.Client, _ = secret.Target.(*cred.Aws)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	sess, err := session.NewSession(&aws.Config{Region: aws.String(config.Client.Region)})
	if err != nil {
		return nil, err
	}
	certURL := fmt.Sprintf("https://cognito-idp.%v.amazonaws.com/%v/.well-known/jwks.json", config.Client.Region, config.Client.PoolId)
	validator := verifier.New(&verifier.Config{CertURL: certURL})
	if err = validator.Init(ctx); err != nil {
		return nil, err
	}

	return &Service{
		client:   cognitoidentityprovider.New(sess),
		config:   config,
		verifier: validator,
	}, nil
}


// ResetCredentials resets a user's credentials
func (s *Service) ResetCredentials(username, newPassword string) error {
	input := &cognitoidentityprovider.AdminSetUserPasswordInput{
		UserPoolId: aws.String(s.config.Client.PoolId),
		Username:   aws.String(username),
		Password:   aws.String(newPassword),
		Permanent:  aws.Bool(true),
	}

	_, err := s.client.AdminSetUserPassword(input)
	if err != nil {
		return fmt.Errorf("failed to reset credentials: %w", err)
	}

	return nil
}
