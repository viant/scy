package custom

import "golang.org/x/crypto/bcrypt"

// HashPassword hashes a plain text password using bcrypt
func HashPassword(password string) (string, error) {
	cost := bcrypt.DefaultCost // You can increase this value for added security
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// CheckPasswordHash compares a plain text password with a hashed password
func CheckPasswordHash(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
