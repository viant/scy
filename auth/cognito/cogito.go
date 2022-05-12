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
	"github.com/viant/scy/cred"
	"reflect"
	"time"
)

type (
	//Service represents cognito client
	Service struct {
		client *cognitoidentityprovider.CognitoIdentityProvider
		config *Config
		cache  *sjwt.Cache
	}
)

func (s *Service) secretHash(username string) string {
	mac := hmac.New(sha256.New, []byte(s.config.Client.Secret))
	mac.Write([]byte(username + s.config.Client.Id))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

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

//VerifyIdentity verifies identity token, it returns jwt claims
func (s *Service) VerifyIdentity(ctx context.Context, rawToken string) (*sjwt.Claims, error) {
	certURL := fmt.Sprintf("https://cognito-idp.%v.amazonaws.com/%v/.well-known/jwks.json", s.config.Client.Region, s.config.PoolID)
	token, err := sjwt.VerifyToken(ctx, rawToken, certURL, s.cache)
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

//Mew creates new cogito auth service
func Mew(ctx context.Context, config *Config) (*Service, error) {
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
	return &Service{
		client: cognitoidentityprovider.New(sess),
		config: config,
		cache:  sjwt.NewCache(),
	}, nil
}
