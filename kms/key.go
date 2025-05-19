package kms

import (
	"context"
	"fmt"
	"github.com/viant/afs"
	"github.com/viant/afs/file"
	"github.com/viant/afs/url"
	"hash/fnv"
	"net"
	"os"
	"sort"
	"strings"
)

// Key represents secret key
type Key struct {
	Raw    string
	Path   string
	Kind   string
	Scheme string
}

// Key returns key data
func (k *Key) Key(ctx context.Context, defaultValue []byte) ([]byte, error) {
	switch k.Kind {
	case "raw":
		return []byte(k.Raw), nil
	case "inline":
		return []byte(k.Path), nil
	case "default":
		return defaultValue, nil
	case "mac":
		return getMacKey()
	case "env":
		key := strings.Trim(k.Path, "/")
		keyData := os.Getenv(key)
		if keyData == "" {
			return nil, fmt.Errorf("env.key %v was empty", key)
		}
		if len(keyData) < 8 {
			return nil, fmt.Errorf("invalid key length, expected min: 8 but had %v", len(keyData))
		}
		return []byte(keyData), nil
	default:
		fs := afs.New()
		return fs.DownloadWithURL(ctx, k.Path)
	}
}

func getMacKey() ([]byte, error) {
	macs, err := getHardwareAddresses()
	if err != nil {
		return nil, err
	}
	sort.Strings(macs)
	hash := fnv.New64()
	for _, s := range macs {
		if _, err = hash.Write([]byte(s)); err != nil {
			return nil, err
		}
	}
	value := hash.Sum(nil)
	result := make([]byte, 8)
	for i := len(value) - 1; i >= 0; i-- {
		result[i] = value[i]
	}
	return result, nil
}

func getHardwareAddresses() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return []string{}, err
	}
	var macs []string
outer:
	for _, ifa := range ifas {
		hardwareAddr := ifa.HardwareAddr.String()
		if hardwareAddr == "" {
			continue
		}
		ad, _ := ifa.Addrs()
		if len(ad) == 0 {
			continue
		}
		for _, c := range ad {
			ipNet, ok := c.(*net.IPNet)
			if !ok {
				continue outer
			}
			if ipNet.IP.To4() == nil {
				continue outer
			}
		}
		macs = append(macs, hardwareAddr)
	}
	return macs, nil
}

// NewKey creates a new key
func NewKey(raw string) (*Key, error) {
	scheme := url.Scheme(raw, file.Scheme)
	path := raw
	if strings.HasPrefix(raw, "projects/") {
		scheme = "gcp"
	}
	_, err := kms.lookup(scheme)
	if err != nil {
		return nil, err
	}
	if path = url.Path(raw); path == "" {
		path = raw
	}
	return &Key{
		Scheme: scheme,
		Raw:    raw,
		Kind:   url.Host(raw),
		Path:   path,
	}, nil
}
