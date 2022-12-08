package aws

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/viant/scy/cred"
	"os"
)

//NewConfig creates aws.Config or error
func NewConfig(ctx context.Context, awsCred *cred.Aws) (*aws.Config, error) {
	if awsCred.Region == "" {
		awsCred.Region = os.Getenv("AWS_REGION")
	}
	var options []func(*config.LoadOptions) error
	if awsCred.Region != "" {
		options = append(options, config.WithRegion(awsCred.Region))
	}
	if awsCred.Endpoint != "" {
		options = append(options, config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{URL: awsCred.Endpoint}, nil
			})))
	}
	if awsCred.Session != nil && awsCred.Session.RoleArn != "" {
		option, err := authWithAssumedRole(ctx, awsCred)
		if err != nil {
			return nil, err
		}
		options = append(options, option)
	} else if awsCred.Key != "" {
		options = append(options, config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{AccessKeyID: awsCred.Key, SecretAccessKey: awsCred.Secret, SessionToken: awsCred.Token},
		}))
	}
	cfg, err := config.LoadDefaultConfig(context.TODO(), options...)
	if err != nil {
		return nil, err
	}
	return &cfg, err
}

func authWithAssumedRole(ctx context.Context, c *cred.Aws) (func(*config.LoadOptions) error, error) {
	var err error
	var cfg aws.Config
	if c.Key != "" {
		cfg = aws.Config{Region: c.Region, Credentials: credentials.NewStaticCredentialsProvider(c.Key, c.Secret, "")}
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
	}
	if err != nil {
		return nil, err
	}
	stsSvc := sts.NewFromConfig(cfg)
	creds := stscreds.NewAssumeRoleProvider(stsSvc, c.Session.RoleArn, func(options *stscreds.AssumeRoleOptions) {
		options.RoleSessionName = c.Session.Name
	})
	return config.WithCredentialsProvider(creds), nil
}
