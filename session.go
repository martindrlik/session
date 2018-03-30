package session

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

var (
	sessionMap = make(map[string]time.Time)
	sessionMut = sync.RWMutex{}
)

// Create creates session with expiration expire.
func Create(expire time.Time) (string, error) {
	tok, err := genToken()
	if err != nil {
		return "", err
	}
	set(tok, expire)
	return tok, nil
}

// IsValid returns true if session for given token is valid,
// false otherwise.
func IsValid(token string, now func() time.Time) bool {
	expire, ok := session(token)
	return ok && now().After(expire)
}

func session(tok string) (time.Time, bool) {
	sessionMut.RLock()
	defer sessionMut.RUnlock()
	expire, ok := sessionMap[tok]
	return expire, ok
}

func genToken() (string, error) {
	b := make([]byte, 18)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	tok := base64.StdEncoding.EncodeToString(b)
	return tok, nil
}

func set(tok string, expire time.Time) {
	sessionMut.Lock()
	defer sessionMut.Unlock()
	sessionMap[tok] = expire
}
