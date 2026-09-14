package cache

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetchRefreshesOnlyExpiredKeys(t *testing.T) {
	for _, mode := range []string{"unexpired hit", "expired rotation", "expired fetch failure"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int64
			var rotated, fail atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				if fail.Load() {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				id := "first"
				if rotated.Load() {
					id = "rotated"
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"oct","kid":%q,"k":"dGVzdC1rZXk"}]}`, id)
			}))
			defer server.Close()
			cache := New()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			initial, err := cache.Fetch(ctx, server.URL)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := initial.LookupKeyID("first"); !ok {
				t.Fatal("initial key missing")
			}
			rotated.Store(true)
			if mode != "unexpired hit" {
				cache.mux.Lock()
				cache.sets[server.URL].expiry = time.Now().Add(-time.Second)
				cache.mux.Unlock()
			}
			fail.Store(mode == "expired fetch failure")
			actual, err := cache.Fetch(ctx, server.URL)
			if mode == "expired fetch failure" {
				if err == nil || actual != nil {
					t.Fatalf("expired key reused after fetch failure: set=%v err=%v", actual, err)
				}
				fail.Store(false)
				actual, err = cache.Fetch(ctx, server.URL)
			}
			if err != nil {
				t.Fatal(err)
			}
			wantID, wantCalls := "rotated", int64(2)
			if mode == "unexpired hit" {
				wantID, wantCalls = "first", 1
			}
			if mode == "expired fetch failure" {
				wantCalls = 3
			}
			if _, ok := actual.LookupKeyID(wantID); !ok || calls.Load() != wantCalls {
				t.Fatalf("key=%s present=%v requests=%d want=%d", wantID, ok, calls.Load(), wantCalls)
			}
			if wantID == "rotated" {
				if _, ok := actual.LookupKeyID("first"); ok {
					t.Fatal("removed key survived refresh")
				}
			}
		})
	}
}
