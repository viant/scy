package ssh

import "golang.org/x/crypto/ssh"

func LoadPrivateKeyWithPassphrase(privateKeyBytes []byte, passphrase string) (ssh.AuthMethod, error) {
	var err error
	// Decrypt the private key with the passphrase
	var signer ssh.Signer
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, []byte(passphrase))
		if err != nil {
			return nil, err
		}
	} else {
		// If there's no passphrase, just parse the private key normally
		signer, err = ssh.ParsePrivateKey(privateKeyBytes)
		if err != nil {
			return nil, err
		}
	}
	// Return the AuthMethod created from the signer
	return ssh.PublicKeys(signer), nil
}
