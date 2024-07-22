package custom

// Subject represent subject
type Subject struct {
	ID       string  `aerospike:"uid,pk=true"`
	Locked   *bool   `aerospike:"locked"`
	Password *string `aerospike:"password"`
	Attempts *int    `aerospike:"attempts"`
}

// IsLocked returns true if the subject is locked
func (s Subject) IsLocked(maxAttempts int) bool {
	if s.Locked == nil {
		return false
	}
	if s.Attempts == nil {
		return false
	}
	return *s.Locked || (maxAttempts > 0 && *s.Attempts > maxAttempts)
}

// Identity represents the identity
type Identity struct {
	ID string `sqlx:"id" aerospike:"id,pk=true"`
}
