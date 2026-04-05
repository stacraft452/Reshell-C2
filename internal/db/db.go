package db

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"c2/internal/config"
	"c2/internal/models"
)

// Init 使用配置初始化 SQLite 数据库，并执行自动迁移。
func Init(cfg *config.Config) (*gorm.DB, error) {
	dbPath := cfg.Database.Path
	if dbPath == "" {
		dbPath = "data/c2.db"
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	gdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// 自动迁移基础表结构
	if err := gdb.AutoMigrate(
		&models.Listener{},
		&models.Client{},
		&models.CommandLog{},
		&models.FileTransfer{},
		&models.Session{},
		&models.Screenshot{},
		&models.Tunnel{},
		&models.Script{},
	); err != nil {
		return nil, fmt.Errorf("auto migrate: %w", err)
	}

	return gdb, nil
}
