// Package httputil contains functionality for working with HTTP.
package httputil

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type mapLock struct {
	mu    sync.Mutex
	byKey map[string]chan struct{}
}

func newMapLock() *mapLock {
	return &mapLock{
		byKey: make(map[string]chan struct{}),
	}
}

func (ml *mapLock) Lock(ctx context.Context, key string) error {
	for {
		ml.mu.Lock()
		ch, locked := ml.byKey[key]
		// take the lock since it doesn't exist yet
		if !locked {
			ch = make(chan struct{})
			ml.byKey[key] = ch
		}
		ml.mu.Unlock()

		// this means we took the lock so return nil
		if !locked {
			return nil
		}

		select {
		case <-ch: // lock was released, so retry
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (ml *mapLock) Unlock(key string) {
	ml.mu.Lock()
	ch, ok := ml.byKey[key]
	delete(ml.byKey, key)
	ml.mu.Unlock()

	// if a channel exists, close it, indicating we've unlocked
	if ok {
		close(ch)
	}
}

// A CachedRoundTripper caches HTTP Responses.
type CachedRoundTripper struct {
	dir        string
	underlying http.RoundTripper
	ttl        time.Duration

	locksByURL *mapLock
}

// NewCachedRoundTripper creates a new CachedRoundTripper.
func NewCachedRoundTripper(dir string, underlying http.RoundTripper, ttl time.Duration) *CachedRoundTripper {
	return &CachedRoundTripper{
		dir:        dir,
		underlying: underlying,
		ttl:        ttl,

		locksByURL: newMapLock(),
	}
}

// RoundTrip performs the round trip.
func (crt *CachedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// only cache GET requests
	if req.Method != http.MethodGet {
		return crt.underlying.RoundTrip(req)
	}

	rawURL := req.URL.String()
	err := crt.locksByURL.Lock(req.Context(), rawURL)
	if err != nil {
		return nil, err
	}
	defer crt.locksByURL.Unlock(rawURL)

	fi, err := crt.readCachedFileInfo(rawURL)
	switch {
	case os.IsNotExist(err):
		// if the error is that the file doesn't exist yet, do the round trip
		err = crt.writeRoundTrip(req)
	case err != nil:
		// otherwise, some other error occurred, so return it
		return nil, err
	case fi.ModTime().Add(crt.ttl).After(time.Now()):
	// use the cached result
	default:
		// any other case, do the round trip
		err = crt.writeRoundTrip(req)
	}
	if err != nil {
		return nil, err
	}

	return crt.readCachedFile(rawURL)

}

func (crt *CachedRoundTripper) writeRoundTrip(req *http.Request) error {
	rawURL := req.URL.String()
	fp := filepath.Join(crt.dir, crt.getFileName(rawURL))
	err := os.MkdirAll(filepath.Dir(fp), 0o700)
	if err != nil {
		return err
	}

	f, err := os.Create(fp)
	if err != nil {
		return err
	}

	res, err := crt.underlying.RoundTrip(req)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(fp)
		return err
	}

	err = res.Write(f)
	if err != nil {
		_ = res.Body.Close()
		_ = f.Close()
		_ = os.Remove(fp)
		return err
	}

	return f.Close()
}

func (crt *CachedRoundTripper) readCachedFile(rawURL string) (*http.Response, error) {
	fp := filepath.Join(crt.dir, crt.getFileName(rawURL))
	bs, err := os.ReadFile(fp)
	if err != nil {
		return nil, err
	}
	buf := bufio.NewReader(bytes.NewReader(bs))
	return http.ReadResponse(buf, nil)
}

func (crt *CachedRoundTripper) readCachedFileInfo(rawURL string) (os.FileInfo, error) {
	fp := filepath.Join(crt.dir, crt.getFileName(rawURL))
	return os.Stat(fp)
}

func (crt *CachedRoundTripper) getFileName(rawURL string) string {
	h := sha256.Sum256([]byte(rawURL))
	return hex.EncodeToString(h[:])
}
