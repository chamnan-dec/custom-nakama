// Copyright 2018 The Nakama Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib" // Blank import to register SQL driver
	"github.com/joho/godotenv"
	"github.com/thaibev/nakama/v3/migrate"
	"github.com/thaibev/nakama/v3/server"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/encoding/protojson"
)

const cookieFilename = ".cookie"

var (
	version  string = "3.0.0"
	commitID string = "dev"

	// Shared utility components.
	jsonpbMarshaler = &protojson.MarshalOptions{
		UseEnumNumbers:  true,
		EmitUnpopulated: false,
		Indent:          "",
		UseProtoNames:   true,
	}
	jsonpbUnmarshaler = &protojson.UnmarshalOptions{
		DiscardUnknown: false,
	}
)

func getDbConfigs() map[string]string {
	// Check if running in Docker (environment variable set)
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "localhost" // Default for local development
	}

	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		dbPort = "6432" // Default PgBouncer port
	}

	dbSSLMode := os.Getenv("DB_SSLMODE")
	if dbSSLMode == "" {
		dbSSLMode = "disable" // Default for local development
	}

	return map[string]string{
		"region_a": fmt.Sprintf("postgresql://postgres:localdb@%s:%s/custom-nakama?sslmode=%s", dbHost, dbPort, dbSSLMode),
		"region_b": fmt.Sprintf("postgresql://postgres:localdb@%s:%s/custom-nakama?sslmode=%s", dbHost, dbPort, dbSSLMode),
	}
}

func init() {
	// Load .env file (ignore error if file doesn't exist in production)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}
}

func main() {
	defer os.Exit(0)

	dbConfigs := getDbConfigs()
	for key, url := range dbConfigs {
		if err := server.SetupPool(key, url); err != nil {
			log.Fatalf("setup pool for %s failed: %v", key, err)
		}
	}

	semver := fmt.Sprintf("%s+%s", version, commitID)
	// Always set default timeout on HTTP client.
	http.DefaultClient.Timeout = 1500 * time.Millisecond

	tmpLogger := server.NewJSONLogger(os.Stdout, zapcore.InfoLevel, server.JSONFormat)

	ctx, ctxCancelFn := context.WithCancel(context.Background())

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version":
			fmt.Println(semver)
			return
		case "migrate":
			config := server.ParseArgs(tmpLogger, os.Args[2:])

			// Run migration for all configured databases
			for dbName := range dbConfigs {
				tmpLogger.Info("Running migration for database", zap.String("db", dbName))

				db, err := server.GetDB(dbName)
				if err != nil {
					tmpLogger.Fatal("Failed to get db pool for migration", zap.String("db", dbName), zap.Error(err))
				}

				conn, err := db.Conn(ctx)
				if err != nil {
					db.Close()
					tmpLogger.Fatal("Failed to acquire db conn for migration", zap.String("db", dbName), zap.Error(err))
				}

				if err = conn.Raw(func(driverConn any) error {
					pgxConn := driverConn.(*stdlib.Conn).Conn()
					migrate.RunCmd(ctx, tmpLogger, pgxConn, os.Args[2], config.GetLimit(), config.GetLogger().Format)
					return nil
				}); err != nil {
					conn.Close()
					db.Close()
					tmpLogger.Fatal("Failed to acquire pgx conn for migration", zap.String("db", dbName), zap.Error(err))
				}

				conn.Close()
				db.Close()
				tmpLogger.Info("Migration completed for database", zap.String("db", dbName))
			}
			return
		case "healthcheck":
			port := "7350"
			if len(os.Args) > 2 {
				port = os.Args[2]
			}

			resp, err := http.Get("http://localhost:" + port)
			if err != nil || resp.StatusCode != http.StatusOK {
				tmpLogger.Fatal("healthcheck failed")
			}
			tmpLogger.Info("healthcheck ok")
			return
		}
	}

	config := server.ParseArgs(tmpLogger, os.Args)
	logger, startupLogger := server.SetupLogging(tmpLogger, config)

	startupLogger.Info("Nakama starting")
	startupLogger.Info("Node", zap.String("name", config.GetName()), zap.String("version", semver), zap.String("runtime", runtime.Version()), zap.Int("cpu", runtime.NumCPU()), zap.Int("proc", runtime.GOMAXPROCS(0)))
	startupLogger.Info("Data directory", zap.String("path", config.GetDataDir()))

	// Start up server components.
	metrics := server.NewLocalMetrics(logger, startupLogger, config)
	sessionRegistry := server.NewLocalSessionRegistry(metrics)
	sessionCache := server.NewLocalSessionCache(config.GetSession().TokenExpirySec, config.GetSession().RefreshTokenExpirySec)
	statusRegistry := server.NewLocalStatusRegistry(logger, config, sessionRegistry, jsonpbMarshaler)
	tracker := server.StartLocalTracker(logger, config, sessionRegistry, statusRegistry, metrics, jsonpbMarshaler)
	router := server.NewLocalMessageRouter(sessionRegistry, tracker, jsonpbMarshaler)
	streamManager := server.NewLocalStreamManager(config, sessionRegistry, tracker)

	// Initialize presign service
	presignService, err := server.NewPresignServiceFromEnv()
	if err != nil {
		logger.Fatal("Failed to initialize presign service", zap.Error(err))
	}

	pipeline := server.NewPipeline(logger, config, jsonpbMarshaler, jsonpbUnmarshaler, sessionRegistry, statusRegistry, tracker, router)

	apiServer := server.StartApiServer(logger, startupLogger, jsonpbMarshaler, jsonpbUnmarshaler, config, version, sessionRegistry, sessionCache, statusRegistry, tracker, router, streamManager, metrics, pipeline, presignService)

	// Respect OS stop signals.
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	startupLogger.Info("Startup done")

	// Wait for a termination signal.
	<-c

	// server.HandleShutdown(ctx, logger, matchRegistry, config.GetShutdownGraceSec(), runtime.Shutdown(), c)

	// Signal cancellation to the global runtime context.
	ctxCancelFn()

	// Gracefully stop remaining server components.
	apiServer.Stop()
	// consoleServer.Stop()
	tracker.Stop()
	statusRegistry.Stop()
	sessionCache.Stop()
	sessionRegistry.Stop()
	metrics.Stop(logger)
	server.CloseAllDbConnection()

	startupLogger.Info("Shutdown complete")
}
