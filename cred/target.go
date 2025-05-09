package cred

import (
	"fmt"
	"reflect"
)

// TargetType returns target type for string
func TargetType(target string) (reflect.Type, error) {
	var result reflect.Type
	switch target {
	case "aws":
		result = reflect.TypeOf(Aws{})
	case "basic":
		result = reflect.TypeOf(Basic{})
	case "jwt":
		result = reflect.TypeOf(JwtConfig{})
	case "sha1":
		result = reflect.TypeOf(SHA1{})
	case "key":
		result = reflect.TypeOf(SecretKey{})
	case "ssh":
		result = reflect.TypeOf(SSH{})
	case "generic":
		result = reflect.TypeOf(Generic{})
	case "oauth2":
		result = reflect.TypeOf(Oauth2Config{})
	case "", "raw":

	default:
		return nil, fmt.Errorf("unknown secret target: %v, avail: [aws, basic, jwt, sha1, ,ssh, generic]", target)
	}
	return result, nil
}
