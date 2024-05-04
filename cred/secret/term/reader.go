package term

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"strings"
	"syscall"
	"time"
)

// ReadingCredentialTimeout represents max time for providing CredentialsFromLocation
var ReadingCredentialTimeout = time.Second * 45

// ReadUserAndPassword reads user and password from terminal
func ReadUserAndPassword(timeout time.Duration) (user string, pass string, err error) {
	return readSecrets("Username", "Password", timeout)
}

// ReadSecretKey reads keyID and Secret from terminal
func ReadSecretKey(timeout time.Duration) (user string, pass string, err error) {
	return readSecrets("Key", "Secret", timeout)
}

func readSecrets(nameLabel, secretLabel string, timeout time.Duration) (name string, secret string, err error) {
	completed := make(chan bool)
	var reader = func() {
		defer func() {
			completed <- true
		}()

		var secret1Bytes, secret2Bytes []byte
		reader := bufio.NewReader(os.Stdin)

		fmt.Printf("Enter %s: ", nameLabel)
		name, _ = reader.ReadString('\n')
		fmt.Printf("Enter %s: ", secretLabel)
		secret1Bytes, err = terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			err = fmt.Errorf("failed to read %s %v", secretLabel, err)
			return
		}
		fmt.Print("\nRetype %s: ", secretLabel)
		secret2Bytes, err = terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			err = fmt.Errorf("failed to read %s %v", secretLabel, err)
			return
		}
		secret := string(secret1Bytes)
		if string(secret2Bytes) != secret {
			err = fmt.Errorf("%s did not match", secretLabel)
		}
	}
	go reader()
	select {
	case <-completed:
	case <-time.After(timeout):
		err = fmt.Errorf("reading secret timeout")
	}
	name = strings.TrimSpace(name)
	secret = strings.TrimSpace(secret)
	return name, secret, err
}
