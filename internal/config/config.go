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

package config

import (
	"crypto/tls"
	"flag"
	"os"
	"path/filepath"
	"regexp"

	"github.com/heroiclabs/nakama-common/runtime"
	"github.com/heroiclabs/nakama/v3/flags"
	"go.uber.org/zap"
)

var usernameRegex = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9._].*[a-zA-Z0-9]$")

// Config interface is the Nakama core configuration.
type Config interface {
	GetName() string
	GetDataDir() string
	GetShutdownGraceSec() int
	GetLogger() *LoggerConfig
	GetMetrics() *MetricsConfig
	GetSession() *SessionConfig
	GetSocket() *SocketConfig
	GetAuth() *AuthConfig
	GetTracker() *TrackerConfig
	GetLimit() int

	Clone() (Config, error)
	// GetRuntimeConfig() (runtime.Config, error)
}

func ParseArgs(logger *zap.Logger, args []string) Config {
	// Parse args to get path to a config file if passed in.
	configFilePath := NewConfig(logger)
	configFileFlagSet := flag.NewFlagSet("nakama", flag.ExitOnError)
	configFileFlagMaker := flags.NewFlagMakerFlagSet(&flags.FlagMakingOptions{
		UseLowerCase: true,
		Flatten:      false,
		TagName:      "yaml",
		TagUsage:     "usage",
	}, configFileFlagSet)

	if _, err := configFileFlagMaker.ParseArgs(configFilePath, args[1:]); err != nil {
		logger.Fatal("Could not parse command line arguments", zap.Error(err))
	}

	// Parse config file if path is set.
	mainConfig := NewConfig(logger)
	mainConfig.Config = configFilePath.Config

	// Override config with those passed from command-line.
	mainFlagSet := flag.NewFlagSet("nakama", flag.ExitOnError)
	mainFlagMaker := flags.NewFlagMakerFlagSet(&flags.FlagMakingOptions{
		UseLowerCase: true,
		Flatten:      false,
		TagName:      "yaml",
		TagUsage:     "usage",
	}, mainFlagSet)

	if _, err := mainFlagMaker.ParseArgs(mainConfig, args[1:]); err != nil {
		logger.Fatal("Could not parse command line arguments", zap.Error(err))
	}

	return mainConfig
}

type config struct {
	Name             string         `yaml:"name" json:"name" usage:"Nakama server’s node name - must be unique."`
	Config           []string       `yaml:"config" json:"config" usage:"The absolute file path to configuration YAML file."`
	ShutdownGraceSec int            `yaml:"shutdown_grace_sec" json:"shutdown_grace_sec" usage:"Maximum number of seconds to wait for the server to complete work before shutting down. Default is 0 seconds. If 0 the server will shut down immediately when it receives a termination signal."`
	Metrics          *MetricsConfig `yaml:"metrics" json:"metrics" usage:"Metrics settings."`
	Datadir          string         `yaml:"data_dir" json:"data_dir" usage:"An absolute path to a writeable folder where Nakama will store its data."`
	Logger           *LoggerConfig  `yaml:"logger" json:"logger" usage:"Logger levels and output."`
	Session          *SessionConfig `yaml:"session" json:"session" usage:"Session authentication settings."`
	Socket           *SocketConfig  `yaml:"socket" json:"socket" usage:"Socket configuration."`
	Tracker          *TrackerConfig `yaml:"tracker" json:"tracker" usage:"Presence tracker properties."`
	Auth             *AuthConfig    `yaml:"auth" json:"auth" usage:"Holds configuration settings related to authentication and token management."`
	Limit            int            `json:"-"` // Only used for migrate command.
}

// NewConfig constructs a Config struct which represents server settings, and populates it with default values.
func NewConfig(logger *zap.Logger) *config {
	cwd, err := os.Getwd()
	if err != nil {
		logger.Fatal("Error getting current working directory.", zap.Error(err))
	}
	return &config{
		Name:             "nakama",
		Datadir:          filepath.Join(cwd, "data"),
		ShutdownGraceSec: 0,
		Logger:           NewLoggerConfig(),
		Session:          NewSessionConfig(),
		Socket:           NewSocketConfig(),
		Tracker:          NewTrackerConfig(),
		Auth:             NewAuthConfig(),

		Limit: -1,
	}
}

func (c *config) Clone() (Config, error) {
	configSocket, err := c.Socket.Clone()
	if err != nil {
		return nil, err
	}

	nc := &config{
		Name:             c.Name,
		Datadir:          c.Datadir,
		ShutdownGraceSec: c.ShutdownGraceSec,
		Logger:           c.Logger.Clone(),
		Metrics:          c.Metrics.Clone(),
		Session:          c.Session.Clone(),
		Socket:           configSocket,
		Tracker:          c.Tracker.Clone(),
		Auth:             c.Auth.Clone(),
		Limit:            c.Limit,
	}

	return nc, nil
}

func (c *config) GetName() string {
	return c.Name
}

func (c *config) GetDataDir() string {
	return c.Datadir
}

func (c *config) GetShutdownGraceSec() int {
	return c.ShutdownGraceSec
}

func (c *config) GetLogger() *LoggerConfig {
	return c.Logger
}

func (c *config) GetMetrics() *MetricsConfig {
	return c.Metrics
}

func (c *config) GetSession() *SessionConfig {
	return c.Session
}

func (c *config) GetSocket() *SocketConfig {
	return c.Socket
}

func (c *config) GetTracker() *TrackerConfig {
	return c.Tracker
}

func (c *config) GetAuth() *AuthConfig {
	return c.Auth
}

func (c *config) GetLimit() int {
	return c.Limit
}

var _ runtime.LoggerConfig = &LoggerConfig{}

// LoggerConfig is configuration relevant to logging levels and output.
type LoggerConfig struct {
	Level    string `yaml:"level" json:"level" usage:"Log level to set. Valid values are 'debug', 'info', 'warn', 'error'. Default 'info'."`
	Stdout   bool   `yaml:"stdout" json:"stdout" usage:"Log to standard console output (as well as to a file if set). Default true."`
	File     string `yaml:"file" json:"file" usage:"Log output to a file (as well as stdout if set). Make sure that the directory and the file is writable."`
	Rotation bool   `yaml:"rotation" json:"rotation" usage:"Rotate log files. Default is false."`
	// Reference: https://godoc.org/gopkg.in/natefinch/lumberjack.v2
	MaxSize    int    `yaml:"max_size" json:"max_size" usage:"The maximum size in megabytes of the log file before it gets rotated. It defaults to 100 megabytes."`
	MaxAge     int    `yaml:"max_age" json:"max_age" usage:"The maximum number of days to retain old log files based on the timestamp encoded in their filename. The default is not to remove old log files based on age."`
	MaxBackups int    `yaml:"max_backups" json:"max_backups" usage:"The maximum number of old log files to retain. The default is to retain all old log files (though MaxAge may still cause them to get deleted.)"`
	LocalTime  bool   `yaml:"local_time" json:"local_time" usage:"This determines if the time used for formatting the timestamps in backup files is the computer's local time. The default is to use UTC time."`
	Compress   bool   `yaml:"compress" json:"compress" usage:"This determines if the rotated log files should be compressed using gzip."`
	Format     string `yaml:"format" json:"format" usage:"Set logging output format. Can either be 'JSON' or 'Stackdriver'. Default is 'JSON'."`
}

func (cfg *LoggerConfig) GetLevel() string {
	return cfg.Level
}

func (cfg *LoggerConfig) Clone() *LoggerConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

func NewLoggerConfig() *LoggerConfig {
	return &LoggerConfig{
		Level:      "info",
		Stdout:     true,
		File:       "",
		Rotation:   false,
		MaxSize:    100,
		MaxAge:     0,
		MaxBackups: 0,
		LocalTime:  false,
		Compress:   false,
		Format:     "json",
	}
}

// MetricsConfig is configuration relevant to metrics capturing and output.
type MetricsConfig struct {
	ReportingFreqSec int    `yaml:"reporting_freq_sec" json:"reporting_freq_sec" usage:"Frequency of metrics exports. Default is 60 seconds."`
	Namespace        string `yaml:"namespace" json:"namespace" usage:"Namespace for Prometheus metrics. It will always prepend node name."`
	PrometheusPort   int    `yaml:"prometheus_port" json:"prometheus_port" usage:"Port to expose Prometheus. If '0' Prometheus exports are disabled."`
	Prefix           string `yaml:"prefix" json:"prefix" usage:"Prefix for metric names. Default is 'nakama', empty string '' disables the prefix."`
	CustomPrefix     string `yaml:"custom_prefix" json:"custom_prefix" usage:"Prefix for custom runtime metric names. Default is 'custom', empty string '' disables the prefix."`
}

func (cfg *MetricsConfig) Clone() *MetricsConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

func NewMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		ReportingFreqSec: 60,
		Namespace:        "",
		PrometheusPort:   0,
		Prefix:           "nakama",
		CustomPrefix:     "custom",
	}
}

var _ runtime.SessionConfig = &SessionConfig{}

// SessionConfig is configuration relevant to the session.
type SessionConfig struct {
	EncryptionKey         string `yaml:"encryption_key" json:"encryption_key" usage:"The encryption key used to produce the client token."`
	TokenExpirySec        int64  `yaml:"token_expiry_sec" json:"token_expiry_sec" usage:"Token expiry in seconds."`
	RefreshEncryptionKey  string `yaml:"refresh_encryption_key" json:"refresh_encryption_key" usage:"The encryption key used to produce the client refresh token."`
	RefreshTokenExpirySec int64  `yaml:"refresh_token_expiry_sec" json:"refresh_token_expiry_sec" usage:"Refresh token expiry in seconds."`
	SingleSocket          bool   `yaml:"single_socket" json:"single_socket" usage:"Only allow one socket per user. Older sessions are disconnected. Default false."`
	SingleMatch           bool   `yaml:"single_match" json:"single_match" usage:"Only allow one match per user. Older matches receive a leave. Requires single socket to enable. Default false."`
	SingleParty           bool   `yaml:"single_party" json:"single_party" usage:"Only allow one party per user. Older parties receive a leave. Requires single socket to enable. Default false."`
	SingleSession         bool   `yaml:"single_session" json:"single_session" usage:"Only allow one session token per user. Older session tokens are invalidated in the session cache. Default false."`
}

func (cfg *SessionConfig) GetEncryptionKey() string {
	return cfg.EncryptionKey
}

func (cfg *SessionConfig) GetTokenExpirySec() int64 {
	return cfg.TokenExpirySec
}

func (cfg *SessionConfig) GetRefreshEncryptionKey() string {
	return cfg.RefreshEncryptionKey
}

func (cfg *SessionConfig) GetRefreshTokenExpirySec() int64 {
	return cfg.RefreshTokenExpirySec
}

func (cfg *SessionConfig) GetSingleSocket() bool {
	return cfg.SingleSocket
}

func (cfg *SessionConfig) GetSingleMatch() bool {
	return cfg.SingleMatch
}

func (cfg *SessionConfig) GetSingleParty() bool {
	return cfg.SingleParty
}

func (cfg *SessionConfig) GetSingleSession() bool {
	return cfg.SingleSession
}

func (cfg *SessionConfig) Clone() *SessionConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

func NewSessionConfig() *SessionConfig {
	return &SessionConfig{
		EncryptionKey:         "defaultencryptionkey",
		TokenExpirySec:        60,
		RefreshEncryptionKey:  "defaultrefreshencryptionkey",
		RefreshTokenExpirySec: 3600,
	}
}

var _ runtime.SocketConfig = &SocketConfig{}

// SocketConfig is configuration relevant to the transport socket and protocol.
type SocketConfig struct {
	ServerKey            string            `yaml:"server_key" json:"server_key" usage:"Server key to use to establish a connection to the server."`
	Port                 int               `yaml:"port" json:"port" usage:"The port for accepting connections from the client for the given interface(s), address(es), and protocol(s). Default 7350."`
	Address              string            `yaml:"address" json:"address" usage:"The IP address of the interface to listen for client traffic on. Default listen on all available addresses/interfaces."`
	Protocol             string            `yaml:"protocol" json:"protocol" usage:"The network protocol to listen for traffic on. Possible values are 'tcp' for both IPv4 and IPv6, 'tcp4' for IPv4 only, or 'tcp6' for IPv6 only. Default 'tcp'."`
	MaxMessageSizeBytes  int64             `yaml:"max_message_size_bytes" json:"max_message_size_bytes" usage:"Maximum amount of data in bytes allowed to be read from the client socket per message. Used for real-time connections."`
	MaxRequestSizeBytes  int64             `yaml:"max_request_size_bytes" json:"max_request_size_bytes" usage:"Maximum amount of data in bytes allowed to be read from clients per request. Used for gRPC and HTTP connections."`
	ReadBufferSizeBytes  int               `yaml:"read_buffer_size_bytes" json:"read_buffer_size_bytes" usage:"Size in bytes of the pre-allocated socket read buffer. Default 4096."`
	WriteBufferSizeBytes int               `yaml:"write_buffer_size_bytes" json:"write_buffer_size_bytes" usage:"Size in bytes of the pre-allocated socket write buffer. Default 4096."`
	ReadTimeoutMs        int               `yaml:"read_timeout_ms" json:"read_timeout_ms" usage:"Maximum duration in milliseconds for reading the entire request. Used for HTTP connections."`
	WriteTimeoutMs       int               `yaml:"write_timeout_ms" json:"write_timeout_ms" usage:"Maximum duration in milliseconds before timing out writes of the response. Used for HTTP connections."`
	IdleTimeoutMs        int               `yaml:"idle_timeout_ms" json:"idle_timeout_ms" usage:"Maximum amount of time in milliseconds to wait for the next request when keep-alives are enabled. Used for HTTP connections."`
	WriteWaitMs          int               `yaml:"write_wait_ms" json:"write_wait_ms" usage:"Time in milliseconds to wait for an ack from the client when writing data. Used for real-time connections."`
	PongWaitMs           int               `yaml:"pong_wait_ms" json:"pong_wait_ms" usage:"Time in milliseconds to wait between pong messages received from the client. Used for real-time connections."`
	PingPeriodMs         int               `yaml:"ping_period_ms" json:"ping_period_ms" usage:"Time in milliseconds to wait between sending ping messages to the client. This value must be less than the pong_wait_ms. Used for real-time connections."`
	PingBackoffThreshold int               `yaml:"ping_backoff_threshold" json:"ping_backoff_threshold" usage:"Minimum number of messages received from the client during a single ping period that will delay the sending of a ping until the next ping period, to avoid sending unnecessary pings on regularly active connections. Default 20."`
	OutgoingQueueSize    int               `yaml:"outgoing_queue_size" json:"outgoing_queue_size" usage:"The maximum number of messages waiting to be sent to the client. If this is exceeded the client is considered too slow and will disconnect. Used when processing real-time connections."`
	SSLCertificate       string            `yaml:"ssl_certificate" json:"ssl_certificate" usage:"Path to certificate file if you want the server to use SSL directly. Must also supply ssl_private_key. NOT recommended for production use."`
	SSLPrivateKey        string            `yaml:"ssl_private_key" json:"ssl_private_key" usage:"Path to private key file if you want the server to use SSL directly. Must also supply ssl_certificate. NOT recommended for production use."`
	ResponseHeaders      []string          `yaml:"response_headers" json:"response_headers" usage:"Additional headers to send to clients with every response. Values here are only used if the response would not otherwise contain a value for the specified headers."`
	Headers              map[string]string `yaml:"-" json:"-"` // Created by parsing ResponseHeaders above, not set from input args directly.
	CertPEMBlock         []byte            `yaml:"-" json:"-"` // Created by fully reading the file contents of SSLCertificate, not set from input args directly.
	KeyPEMBlock          []byte            `yaml:"-" json:"-"` // Created by fully reading the file contents of SSLPrivateKey, not set from input args directly.
	TLSCert              []tls.Certificate `yaml:"-" json:"-"` // Created by processing CertPEMBlock and KeyPEMBlock, not set from input args directly.
}

func (cfg *SocketConfig) GetServerKey() string {
	return cfg.ServerKey
}

func (cfg *SocketConfig) GetPort() int {
	return cfg.Port
}

func (cfg *SocketConfig) GetAddress() string {
	return cfg.Address
}

func (cfg *SocketConfig) GetProtocol() string {
	return cfg.Protocol
}

func (cfg *SocketConfig) Clone() (*SocketConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	cfgCopy := *cfg

	if cfg.ResponseHeaders != nil {
		cfgCopy.ResponseHeaders = make([]string, len(cfg.ResponseHeaders))
		copy(cfgCopy.ResponseHeaders, cfg.ResponseHeaders)
	}
	if cfg.Headers != nil {
		cfgCopy.Headers = make(map[string]string, len(cfg.Headers))
		for k, v := range cfg.Headers {
			cfgCopy.Headers[k] = v
		}
	}
	if cfg.CertPEMBlock != nil {
		cfgCopy.CertPEMBlock = make([]byte, len(cfg.CertPEMBlock))
		copy(cfgCopy.CertPEMBlock, cfg.CertPEMBlock)
	}
	if cfg.KeyPEMBlock != nil {
		cfgCopy.KeyPEMBlock = make([]byte, len(cfg.KeyPEMBlock))
		copy(cfgCopy.KeyPEMBlock, cfg.KeyPEMBlock)
	}
	if len(cfg.TLSCert) != 0 {
		cert, err := tls.X509KeyPair(cfg.CertPEMBlock, cfg.KeyPEMBlock)
		if err != nil {
			return nil, err
		}
		cfgCopy.TLSCert = []tls.Certificate{cert}
	}

	return &cfgCopy, nil
}

func NewSocketConfig() *SocketConfig {
	return &SocketConfig{
		ServerKey:            "defaultkey",
		Port:                 7350,
		Address:              "",
		Protocol:             "tcp",
		MaxMessageSizeBytes:  4096,
		MaxRequestSizeBytes:  262_144, // 256 KB.
		ReadBufferSizeBytes:  4096,
		WriteBufferSizeBytes: 4096,
		ReadTimeoutMs:        10 * 1000,
		WriteTimeoutMs:       10 * 1000,
		IdleTimeoutMs:        60 * 1000,
		WriteWaitMs:          5000,
		PongWaitMs:           25000,
		PingPeriodMs:         15000,
		PingBackoffThreshold: 20,
		OutgoingQueueSize:    64,
		SSLCertificate:       "",
		SSLPrivateKey:        "",
	}
}

// TrackerConfig is configuration relevant to the presence tracker.
type TrackerConfig struct {
	EventQueueSize int `yaml:"event_queue_size" json:"event_queue_size" usage:"Size of the tracker presence event buffer. Increase if the server is expected to generate a large number of presence events in a short time. Default 1024."`
}

func (cfg *TrackerConfig) Clone() *TrackerConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

func NewTrackerConfig() *TrackerConfig {
	return &TrackerConfig{
		EventQueueSize: 1024,
	}
}

// AuthConfig holds configuration settings related to authentication and token management.
type AuthConfig struct {
	SecretKey string `yaml:"secret_key" json:"secret_key" usage:"Secret key used to sign and verify authentication tokens. Must be kept private and consistent across server restarts."`
}

func (cfg *AuthConfig) Clone() *AuthConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

func NewAuthConfig() *AuthConfig {
	return &AuthConfig{
		SecretKey: "DEFAULT_SECRET_KEY",
	}
}
