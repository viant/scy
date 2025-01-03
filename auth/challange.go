package auth

// Challenge represents challenge
type Challenge struct {
	Challenge string `json:"challenge"`
}

// Error returns challenge erro
// Error returns challenge error
func (c Challenge) Error() string {
	return c.Challenge
}

// NewChallenge creates a new challenge error
func NewChallenge(challenge string) *Challenge {
	return &Challenge{
		Challenge: challenge,
	}
}
