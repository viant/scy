package xades

import (
	"testing"
	"time"
)

func FuzzVerifyDoesNotPanic(f *testing.F) {
	identity := newTestIdentity(f, 200)
	at := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	valid, err := SignEnveloped([]byte(`<Document><Value>seed</Value></Document>`), identity, &Options{SigningTime: at})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`<Document/>`))
	f.Add([]byte(`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Verify(input, identity.Certificate, at)
	})
}
