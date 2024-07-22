package custom

import "fmt"

// AuthError represents an authentication error
type AuthError struct {
	reason error
	err    error
}

// Reason returns the reason for the authentication error
func (e *AuthError) Reason() error {
	return e.reason
}

// Error returns the error message
func (e *AuthError) Error() string {
	return e.err.Error()
}

func newAuthError(reason error) *AuthError {
	return &AuthError{reason: reason, err: fmt.Errorf("authentication failed")}
}
