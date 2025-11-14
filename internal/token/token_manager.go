package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

type TokenManager struct {
	secretKey []byte
	apiKeys   map[string]string
	mu        sync.RWMutex
}

var (
	managerInstance *TokenManager
	once            sync.Once
)

// InitTokenManager now accepts secretKey as parameter
func InitTokenManager(secretKey string) *TokenManager {
	once.Do(func() {
		if secretKey == "" {
			panic("secret key cannot be empty")
		}
		managerInstance = &TokenManager{
			secretKey: []byte(secretKey),
			apiKeys: map[string]string{
				"key123": "postgres://user:pass@localhost:5432/dbname?search_path=tenant1",
				"key456": "postgres://user:pass@localhost:5432/dbname?search_path=tenant2",
			},
		}
	})
	return managerInstance
}

func GetTokenManager() *TokenManager {
	if managerInstance == nil {
		panic("TokenManager not initialized, call InitTokenManager() first")
	}
	return managerInstance
}

func (tm *TokenManager) GenerateToken(userID, apiKey string) (string, error) {
	tm.mu.RLock()
	_, ok := tm.apiKeys[apiKey]
	tm.mu.RUnlock()
	if !ok {
		return "", errors.New("invalid API key")
	}

	h := hmac.New(sha256.New, tm.secretKey)
	h.Write([]byte(userID + "|" + apiKey))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (tm *TokenManager) ValidateToken(userID, apiKey, token string) bool {
	tm.mu.RLock()
	_, ok := tm.apiKeys[apiKey]
	tm.mu.RUnlock()
	if !ok {
		return false
	}

	h := hmac.New(sha256.New, tm.secretKey)
	h.Write([]byte(userID + "|" + apiKey))
	expected := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(token))
}
