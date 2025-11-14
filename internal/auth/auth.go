package auth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"sync"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/thaibev/nakama/v3/internal/config"
)

var (
	manager     *TokenManager
	managerOnce sync.Once
)

// DBPool เก็บ connection และ APIKey
type DBPool struct {
	DB     *sql.DB
	DBURL  string
	APIKey string
}

// TokenManager จัดการ token และ DB pools
type TokenManager struct {
	secretKey string
	dbPools   map[string]*DBPool // key = TenantID
	mu        sync.RWMutex
}

// InitTokenManager จะเรียกครั้งแรกตอน app start
func InitTokenManager(authConfig *config.AuthConfig) {
	managerOnce.Do(func() {
		manager = &TokenManager{
			secretKey: authConfig.SecretKey,
			dbPools:   make(map[string]*DBPool),
		}
	})
}

// GetManager คืน singleton instance
func GetManager() *TokenManager {
	if manager == nil {
		panic("TokenManager not initialized. Call InitTokenManager first")
	}
	return manager
}

// GenerateToken ใช้ userID + APIKey + secretKey (หา tenantID จาก dbPools)
func (m *TokenManager) GenerateToken(userID, apiKey string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var tenantID string
	found := false
	for tID, pool := range m.dbPools {
		if pool.APIKey == apiKey {
			tenantID = tID
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("invalid APIKey: %s", apiKey)
	}

	data := fmt.Sprintf("%s:%s:%s:%s", userID, apiKey, tenantID, m.secretKey)
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

func (m *TokenManager) GetTenantID(userID, apiKey string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var tenantID string
	found := false
	for tID, pool := range m.dbPools {
		if pool.APIKey == apiKey {
			tenantID = tID
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("invalid APIKey: %s", apiKey)
	}

	return tenantID, nil
}

// SetupDBPool สร้างและเก็บ DB connection pool
// tenantID = key ของ map, apiKey เก็บใน struct
func (m *TokenManager) SetupDBPool(tenantID, dbURL, apiKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Printf("Create DB Connection for tenant %s with APIKey %s\n", tenantID, apiKey)

	if _, exists := m.dbPools[tenantID]; exists {
		return fmt.Errorf("db pool for tenant '%s' already exists", tenantID)
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}

	m.dbPools[tenantID] = &DBPool{
		DB:     db,
		DBURL:  dbURL,
		APIKey: apiKey,
	}

	return nil
}

// GetDB คืน connection pool ตาม tenantID
func (m *TokenManager) GetDB(tenantID string) (*sql.DB, error) {
	m.mu.RLock()
	pool, ok := m.dbPools[tenantID]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no db pool for tenant '%s'", tenantID)
	}
	return pool.DB, nil
}

func (m *TokenManager) GetDBFromAPIKey(apiKey string) (*sql.DB, error) {
	var db *sql.DB
	found := false

	m.mu.RLock()
	for _, pool := range m.dbPools {
		if pool.APIKey == apiKey {
			db = pool.DB
			found = true
			break
		}
	}
	m.mu.RUnlock()
	if !found {
		return nil, fmt.Errorf("invalid APIKey: %s", apiKey)
	}

	return db, nil
}

// GetAPIKey คืนค่า APIKey จาก tenantID
func (m *TokenManager) GetAPIKey(tenantID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pool, ok := m.dbPools[tenantID]
	if !ok {
		return "", fmt.Errorf("no db pool for tenant '%s'", tenantID)
	}
	return pool.APIKey, nil
}

// CloseAllDB ปิดทุก pool
func (m *TokenManager) CloseAllDB() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for k, pool := range m.dbPools {
		pool.DB.Close()
		delete(m.dbPools, k)
	}
}

// IsValidTenant ตรวจว่า tenantID อยู่ใน dbPools หรือไม่
func (m *TokenManager) IsValidTenant(tenantID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.dbPools[tenantID]
	return ok
}

// IsValidAPIKey ตรวจว่า APIKey อยู่ใน dbPools หรือไม่
func (m *TokenManager) IsValidAPIKey(apiKey string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, pool := range m.dbPools {
		if pool.APIKey == apiKey {
			return true
		}
	}
	return false
}
