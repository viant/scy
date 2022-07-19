package cache

import (
	"context"
	"github.com/lestrrat-go/jwx/jwk"
	"sync"
	"time"
)

var refreshDuration = 15 * time.Minute

type (
	//Cache Represents public key cache
	Cache struct {
		mux  sync.RWMutex
		sets map[string]*entry
	}

	entry struct {
		set    jwk.Set
		expiry time.Time
	}
)

//Fetch return from cache or get token from URL
func (c *Cache) Fetch(ctx context.Context, certURL string) (jwk.Set, error) {
	c.mux.RLock()
	anEntry, ok := c.sets[certURL]
	c.mux.RUnlock()
	if !ok || anEntry.expiry.After(time.Now()) {
		keySet, err := jwk.Fetch(ctx, certURL)
		if err != nil {
			return nil, err
		}
		anEntry = &entry{
			set:    keySet,
			expiry: time.Now().Add(refreshDuration),
		}
		c.mux.Lock()
		c.sets[certURL] = anEntry
		c.mux.Unlock()
	}
	return anEntry.set, nil
}

func New() *Cache {
	return &Cache{
		sets: map[string]*entry{},
	}
}
