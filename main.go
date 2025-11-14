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

	_ "github.com/jackc/pgx/v5/stdlib" // Blank import to register SQL driver
	"github.com/thaibev/nakama/v3/internal/auth"
	"github.com/thaibev/nakama/v3/internal/config"
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

type DBConfig struct {
	DBURL  string
	APIKey string
}

// Map ใช้ TenantID เป็น key
var dbConfigs = map[string]DBConfig{
	"tenant_id_for_one_bangkok_aAdweds2341SFvwe222": {
		DBURL:  "postgresql://postgres:PVzppFXsDTIJHwYWziXmpItGKVZQCvQW@shinkansen.proxy.rlwy.net:37342/railway?sslmode=require&options=-c%20search_path=sook-app",
		APIKey: "api_key_for_tenant_one_bangkok_eASmCjXhaakpSlpH0JQlaOaLTcuJJRd8",
	},
	"tenant_id_for_gateway_bangsue_aAdweds2341SFvwe333": {
		DBURL:  "postgresql://postgres:aaRGhDJRtiHyJhcXntEnyWvyQRenkGXQ@mainline.proxy.rlwy.net:16983/sook?sslmode=require&options=-c%20search_path=public",
		APIKey: "api_key_for_tenant_gateway_bangsue_hO9uMZT2W0CIVdHNuhvtnmRc4G62Giw9",
	},
}

func main() {
	defer os.Exit(0)

	semver := fmt.Sprintf("%s+%s", version, commitID)
	// Always set default timeout on HTTP client.
	http.DefaultClient.Timeout = 1500 * time.Millisecond

	tmpLogger := server.NewJSONLogger(os.Stdout, zapcore.InfoLevel, server.JSONFormat)

	_, ctxCancelFn := context.WithCancel(context.Background())

	config := config.ParseArgs(tmpLogger, os.Args)
	logger, startupLogger := server.SetupLogging(tmpLogger, config)

	auth.InitTokenManager(config.GetAuth())
	tokenManager := auth.GetManager()

	for tenantID, cfg := range dbConfigs {
		if err := tokenManager.SetupDBPool(tenantID, cfg.DBURL, cfg.APIKey); err != nil {
			log.Fatalf("failed to setup DB pool for tenant %s: %v", tenantID, err)
		}
	}

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

	pipeline := server.NewPipeline(logger, config, jsonpbMarshaler, jsonpbUnmarshaler, sessionRegistry, statusRegistry, tracker, router)

	apiServer := server.StartApiServer(logger, startupLogger, jsonpbMarshaler, jsonpbUnmarshaler, config, version, sessionRegistry, sessionCache, statusRegistry, tracker, router, streamManager, metrics, pipeline)

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
