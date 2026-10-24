package secret_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/viant/scy/cred/secret"
)

func rotate(t *testing.T, file, value string) {
	t.Helper()
	temp := file + ".next"
	if err := os.WriteFile(temp, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temp, file); err != nil {
		t.Fatal(err)
	}
}

func TestLookupFreshDoesNotChangeCachedSecrets(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	bearer, key := filepath.Join(dir, "bearer.token"), filepath.Join(dir, "signing.key")
	rotate(t, bearer, "first-fixture-bearer")
	rotate(t, key, "first-fixture-key")
	svc := secret.New()
	cached, err := svc.Lookup(ctx, secret.Resource(bearer))
	if err != nil {
		t.Fatal(err)
	}
	cachedKey, err := svc.Lookup(ctx, secret.Resource(key))
	if err != nil {
		t.Fatal(err)
	}
	rotate(t, bearer, "second-fixture-bearer")
	rotate(t, key, "second-fixture-key")
	fresh, err := svc.LookupFresh(ctx, secret.Resource(bearer))
	if err != nil {
		t.Fatal(err)
	}
	if fresh.String() != "second-fixture-bearer" {
		t.Fatal("fresh lookup did not reload the resource")
	}
	again, err := svc.Lookup(ctx, secret.Resource(bearer))
	if err != nil {
		t.Fatal(err)
	}
	if again != cached || again.String() != "first-fixture-bearer" {
		t.Fatal("fresh lookup changed the ordinary cache")
	}
	againKey, err := svc.Lookup(ctx, secret.Resource(key))
	if err != nil {
		t.Fatal(err)
	}
	if againKey != cachedKey {
		t.Fatal("unrelated cached key was changed")
	}
	if err := os.Remove(bearer); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LookupFresh(ctx, secret.Resource(bearer)); err == nil {
		t.Fatal("missing resource reused a cached bearer")
	}
	again, err = svc.Lookup(ctx, secret.Resource(bearer))
	if err != nil || again != cached {
		t.Fatal("failed fresh lookup invalidated the ordinary cache")
	}
}

func TestLookupFreshHonorsCancellation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "bearer.token")
	rotate(t, file, "fixture-bearer")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := secret.New().LookupFresh(ctx, secret.Resource(file)); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled fresh lookup did not fail closed")
	}
}

func TestConcurrentLookupAndFreshRotation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "bearer.token")
	rotate(t, file, "fixture-one")
	svc := secret.New()
	if _, err := svc.Lookup(context.Background(), secret.Resource(file)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 30; n++ {
				value, err := svc.LookupFresh(context.Background(), secret.Resource(file))
				if err != nil {
					errs <- err
					return
				}
				if value.String() != "fixture-one" && value.String() != "fixture-two" {
					errs <- errors.New("fresh lookup returned an invalid rotation snapshot")
					return
				}
				cached, err := svc.Lookup(context.Background(), secret.Resource(file))
				if err != nil {
					errs <- err
					return
				}
				if cached.String() != "fixture-one" {
					errs <- errors.New("ordinary cached value changed during refresh")
					return
				}
			}
		}()
	}
	for n := 0; n < 30; n++ {
		value := "fixture-one"
		if n%2 == 0 {
			value = "fixture-two"
		}
		rotate(t, file, value)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
