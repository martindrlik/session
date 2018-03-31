package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	// ErrNoSpaceLeft indicates that there is no space for adding new session to session storage.
	ErrNoSpaceLeft = errors.New("no space left for new session")
)

var (
	// MaxSessions is maximum sessions that can be added to session storage.
	MaxSessions int
)

var (
	sessionMap = make(map[string]time.Time)
	sessionMut = sync.RWMutex{}
)

// Create creates session with expiration expire.
func Create(expire time.Time) (string, error) {
	noSpaceLeft := func() bool {
		sessionMut.RLock()
		defer sessionMut.RUnlock()
		return len(sessionMap) >= MaxSessions
	}()
	if noSpaceLeft {
		return "", ErrNoSpaceLeft
	}
	tok, err := genToken()
	if err != nil {
		return "", err
	}
	set(tok, expire)
	return tok, nil
}

// Clean removes expired sessions.
func Clean(now time.Time) {
	toks, ok := collect(now)
	if !ok {
		return
	}
	sessionMut.Lock()
	defer sessionMut.Unlock()
	for _, tok := range toks {
		delete(sessionMap, tok)
	}
}

func collect(now time.Time) ([]string, bool) {
	sessionMut.RLock()
	defer sessionMut.RUnlock()
	if len(sessionMap) < MaxSessions {
		return nil, false
	}
	toks := make([]string, 0)
	for tok, expire := range sessionMap {
		if now.After(expire) {
			toks = append(toks, tok)
		}
	}
	return toks, len(toks) > 0
}

// IsValid returns true if session for given token is valid,
// false otherwise.
func IsValid(token string, now time.Time) bool {
	expire, ok := session(token)
	return ok && now.After(expire)
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
