module github.com/viant/scy

go 1.22

toolchain go1.22.5

require (
	cloud.google.com/go/compute/metadata v0.3.0
	firebase.google.com/go/v4 v4.14.0
	github.com/aws/aws-sdk-go v1.51.23
	github.com/aws/aws-sdk-go-v2 v1.30.3
	github.com/aws/aws-sdk-go-v2/config v1.27.11
	github.com/aws/aws-sdk-go-v2/credentials v1.17.26
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.3
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/jessevdk/go-flags v1.5.0
	github.com/lestrrat-go/jwx v1.2.29
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.9.0
	github.com/viant/afs v1.25.1-0.20231110184132-877ed98abca1
	github.com/viant/afsc v1.9.1
	github.com/viant/datly v0.8.11
	github.com/viant/sqlparser v0.7.1-0.20240717151907-216ea35d127a
	github.com/viant/sqlx v0.12.1-0.20240613223731-980e9de11f2f
	github.com/viant/toolbox v0.36.0
	golang.org/x/crypto v0.22.0
	golang.org/x/oauth2 v0.19.0
	google.golang.org/api v0.174.0
)

require (
	cloud.google.com/go v0.112.1 // indirect
	cloud.google.com/go/auth v0.2.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.0 // indirect
	cloud.google.com/go/firestore v1.15.0 // indirect
	cloud.google.com/go/iam v1.1.7 // indirect
	cloud.google.com/go/longrunning v0.5.5 // indirect
	cloud.google.com/go/secretmanager v1.11.5 // indirect
	cloud.google.com/go/storage v1.40.0 // indirect
	github.com/MicahParks/keyfunc v1.9.0 // indirect
	github.com/aerospike/aerospike-client-go v4.5.2+incompatible // indirect
	github.com/aerospike/aerospike-client-go/v6 v6.15.1 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.11 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.15 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.15 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.4 // indirect
	github.com/aws/smithy-go v1.20.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.12.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/viant/aerospike v0.0.0-20240722133740-00e541ae8f36 // indirect
	github.com/viant/cloudless v1.9.8 // indirect
	github.com/viant/gmetric v0.3.1-0.20230405233616-cc90deee60c4 // indirect
	github.com/viant/godiff v0.4.1 // indirect
	github.com/viant/govalidator v0.2.2 // indirect
	github.com/viant/igo v0.2.0 // indirect
	github.com/viant/parsly v0.3.3-0.20240717150634-e1afaedb691b // indirect
	github.com/viant/structology v0.5.6-0.20240715114555-e89beafaa7b8 // indirect
	github.com/viant/structql v0.4.2-0.20240712002135-b1ef22dd834f // indirect
	github.com/viant/tagly v0.2.1-0.20240521205717-55de744e893c // indirect
	github.com/viant/velty v0.2.1-0.20230927172116-ba56497b5c85 // indirect
	github.com/viant/x v0.3.0 // indirect
	github.com/viant/xdatly v0.3.1-0.20240710035338-b561698d2bf4 // indirect
	github.com/viant/xdatly/extension v0.0.0-20231013204918-ecf3c2edf259 // indirect
	github.com/viant/xdatly/handler v0.0.0-20240710035338-b561698d2bf4 // indirect
	github.com/viant/xdatly/types/core v0.0.0-20240109065401-9758ebacb4bb // indirect
	github.com/viant/xdatly/types/custom v0.0.0-20240624200855-79bbed0d3db9 // indirect
	github.com/viant/xmlify v0.1.1-0.20231127181625-8a6b48ceea12 // indirect
	github.com/viant/xreflect v0.6.2 // indirect
	github.com/viant/xunsafe v0.9.3-0.20240530173106-69808f27713b // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.49.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 // indirect
	go.opentelemetry.io/otel v1.24.0 // indirect
	go.opentelemetry.io/otel/metric v1.24.0 // indirect
	go.opentelemetry.io/otel/trace v1.24.0 // indirect
	golang.org/x/mod v0.16.0 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/term v0.19.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/appengine/v2 v2.0.2 // indirect
	google.golang.org/genproto v0.0.0-20240227224415-6ceb2ff114de // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240314234333-6e1732d8331c // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240415180920-8c6c420018be // indirect
	google.golang.org/grpc v1.63.2 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
