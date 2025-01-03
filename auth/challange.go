package auth

const NewPasswordRequired = "NEW_PASSWORD_REQUIRED"

// ChallengeError represents challenge
type ChallengeError struct {
	Challenge string `json:"challenge"`
}

// Error returns challenge error
func (c *ChallengeError) Error() string {
	return c.Challenge
}

// IsNewPasswordRequired returns true if new password is required
func (c *ChallengeError) IsNewPasswordRequired() bool {
	switch c.Challenge {
	case NewPasswordRequired:
		return true
	}
	return false
}

// NewChallengeError creates a new challenge error
func NewChallengeError(challenge string) *ChallengeError {
	return &ChallengeError{
		Challenge: challenge,
	}
}
