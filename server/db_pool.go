package server

import (
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver
)

var (
	dbPools = make(map[string]*sql.DB)
	mu      sync.RWMutex
)

// SetupPool สร้างและเก็บ connection pool ล่วงหน้า
// ถ้ามี key ซ้ำจะ return error เพื่อกัน override โดยไม่ตั้งใจ
func SetupPool(key string, dbURL string) error {
	mu.Lock()
	defer mu.Unlock()

	fmt.Println("Config DB key: " + key)
	if _, exists := dbPools[key]; exists {
		return fmt.Errorf("db pool for key '%s' already exists", key)
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return fmt.Errorf("failed to open db: %w", err)
	}

	// ปรับ tuning เพื่อ performance
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(0)

	// ทดสอบเชื่อมต่อก่อนเก็บใน cache
	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping db: %w", err)
	}

	dbPools[key] = db
	return nil
}

// GetDB ดึง pool จาก cache เท่านั้น (ห้ามสร้างใหม่)
func GetDB(key string) (*sql.DB, error) {
	mu.RLock()
	db, exists := dbPools[key]
	mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no db pool found for key '%s'", key)
	}
	return db, nil
}

// CloseAll ปิดทุก pool (เช่นตอน shutdown)
func CloseAllDbConnection() {
	mu.Lock()
	defer mu.Unlock()

	for key, db := range dbPools {
		db.Close()
		delete(dbPools, key)
	}
}
