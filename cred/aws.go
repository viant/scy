package cred

// Aws represents AWS credentials
type (
	Aws struct {
		Id       string      `json:",omitempty"`
		Endpoint string      `json:",omitempty"`
		Region   string      `json:",omitempty"`
		Token    string      `json:",omitempty"`
		Session  *AwsSession `json:",omitempty"`
		SecretKey
	}

	AwsSession struct {
		RoleArn string `json:",omitempty"`
		Name    string `json:",omitempty"`
	}
)
