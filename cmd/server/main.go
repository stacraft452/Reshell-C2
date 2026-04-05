package main

import (
	"log"

	"c2/internal/config"
	"c2/internal/db"
	"c2/internal/server"
)

func main() {
	// 加载配置
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	// 初始化数据库
	gdb, err := db.Init(cfg)
	if err != nil {
		log.Fatalf("init db failed: %v", err)
	}

	// 初始化并启动 HTTP 服务
	srv := server.New(cfg, gdb)
	if err := srv.Run(); err != nil {
		log.Fatalf("server exited with error: %v", err)
	}
}

