package gcp

//Scopes defines default auth scopes
var Scopes = []string{
	"openid",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/compute",
	"https://www.googleapis.com/auth/accounts.reauth",
}
