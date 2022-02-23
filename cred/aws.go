package cred

//Aws represents AWS credentials
type Aws struct {
	Key    string `json:",omitempty"`
	Secret string `json:",omitempty"`
	Region string `json:",omitempty"`
}
