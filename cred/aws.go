package cred

//Aws represents AWS credentials
type Aws struct {
	Id     string `json:",omitempty"`
	Key    string `json:",omitempty"`
	Secret string `json:",omitempty"`
	Region string `json:",omitempty"`
}
