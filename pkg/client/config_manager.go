package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/vitalvas/goradius/pkg/log"
	"gopkg.in/yaml.v3"
)

// ConfigManager manages client configuration with dynamic updates
type ConfigManager struct {
	config        *Config
	configFile    string
	logger        log.Logger
	watchers      []ConfigWatcher
	watchersMu    sync.RWMutex
	mu            sync.RWMutex
	updateChan    chan *Config
	stopChan      chan struct{}
	fileModTime   time.Time
	checkInterval time.Duration
}

// ConfigWatcher defines the interface for configuration change notifications
type ConfigWatcher interface {
	OnConfigUpdate(oldConfig, newConfig *Config) error
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(configFile string, logger log.Logger) *ConfigManager {
	if logger == nil {
		logger = log.NewDefaultLogger()
	}

	return &ConfigManager{
		configFile:    configFile,
		logger:        logger,
		watchers:      make([]ConfigWatcher, 0),
		updateChan:    make(chan *Config, 10),
		stopChan:      make(chan struct{}),
		checkInterval: 5 * time.Second,
	}
}

// LoadConfig loads configuration from file
func (cm *ConfigManager) LoadConfig() (*Config, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.configFile == "" {
		// Return default configuration if no file specified
		config := DefaultConfig()
		cm.config = config
		cm.logger.Info("Using default configuration")
		return config, nil
	}

	// Check if file exists
	fileInfo, err := os.Stat(cm.configFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default configuration file with example server
			config := DefaultConfig()
			config.Servers = []ServerConfig{
				{
					Address:      "localhost",
					Port:         1812,
					SharedSecret: []byte("testing123"),
					Priority:     1,
					Weight:       1,
					Timeout:      5 * time.Second,
				},
			}
			err = cm.saveConfigLocked(config)
			if err != nil {
				return nil, fmt.Errorf("failed to create default configuration file: %w", err)
			}
			cm.config = config
			cm.fileModTime = time.Now()
			cm.logger.Infof("Created default configuration file: %s", cm.configFile)
			return config, nil
		}
		return nil, fmt.Errorf("failed to check configuration file: %w", err)
	}

	// Read configuration file
	data, err := os.ReadFile(cm.configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Parse YAML
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration file: %w", err)
	}

	// Validate configuration
	err = validateConfig(&config)
	if err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Apply default values where needed
	cm.applyDefaults(&config)

	cm.config = &config
	cm.fileModTime = fileInfo.ModTime()
	cm.logger.Infof("Loaded configuration from: %s", cm.configFile)

	return &config, nil
}

// SaveConfig saves configuration to file
func (cm *ConfigManager) SaveConfig(config *Config) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.saveConfigLocked(config)
}

// saveConfigLocked saves configuration to file (assumes mutex is already held)
func (cm *ConfigManager) saveConfigLocked(config *Config) error {
	if cm.configFile == "" {
		return fmt.Errorf("no configuration file specified")
	}

	// Validate configuration before saving
	err := validateConfig(config)
	if err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Write to file
	err = os.WriteFile(cm.configFile, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	cm.config = config
	cm.fileModTime = time.Now()

	cm.logger.Infof("Saved configuration to: %s", cm.configFile)

	return nil
}

// GetConfig returns the current configuration
func (cm *ConfigManager) GetConfig() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.config == nil {
		return DefaultConfig()
	}

	// Return a deep copy to prevent external modification
	return cm.copyConfig(cm.config)
}

// UpdateConfig updates the configuration
func (cm *ConfigManager) UpdateConfig(config *Config) error {
	// Validate new configuration
	err := validateConfig(config)
	if err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	cm.mu.Lock()
	oldConfig := cm.config
	cm.config = cm.copyConfig(config)
	cm.mu.Unlock()

	// Notify watchers
	err = cm.notifyWatchers(oldConfig, config)
	if err != nil {
		cm.logger.Errorf("Configuration update notification failed: %v", err)
		// Don't return error as configuration was updated successfully
	}

	// Save to file if file is specified
	if cm.configFile != "" {
		err = cm.SaveConfig(config)
		if err != nil {
			cm.logger.Errorf("Failed to save configuration to file: %v", err)
		}
	}

	cm.logger.Info("Configuration updated successfully")

	return nil
}

// StartWatching starts watching for configuration file changes
func (cm *ConfigManager) StartWatching(ctx context.Context) {
	if cm.configFile == "" {
		cm.logger.Debug("No configuration file to watch")
		return
	}

	cm.logger.Infof("Starting configuration file watching: %s", cm.configFile)

	ticker := time.NewTicker(cm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			cm.logger.Info("Stopping configuration file watching")
			return
		case <-cm.stopChan:
			cm.logger.Info("Configuration file watching stopped")
			return
		case <-ticker.C:
			cm.checkFileChanges()
		}
	}
}

// StopWatching stops watching for configuration file changes
func (cm *ConfigManager) StopWatching() {
	close(cm.stopChan)
}

// checkFileChanges checks if the configuration file has been modified
func (cm *ConfigManager) checkFileChanges() {
	if cm.configFile == "" {
		return
	}

	fileInfo, err := os.Stat(cm.configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			cm.logger.Errorf("Failed to check configuration file: %v", err)
		}
		return
	}

	cm.mu.RLock()
	lastModTime := cm.fileModTime
	cm.mu.RUnlock()

	if fileInfo.ModTime().After(lastModTime) {
		cm.logger.Info("Configuration file changed, reloading...")

		oldConfig := cm.GetConfig()
		newConfig, err := cm.LoadConfig()
		if err != nil {
			cm.logger.Errorf("Failed to reload configuration: %v", err)
			return
		}

		// Notify watchers
		err = cm.notifyWatchers(oldConfig, newConfig)
		if err != nil {
			cm.logger.Errorf("Configuration reload notification failed: %v", err)
		}

		cm.logger.Info("Configuration reloaded successfully")
	}
}

// AddWatcher adds a configuration watcher
func (cm *ConfigManager) AddWatcher(watcher ConfigWatcher) {
	cm.watchersMu.Lock()
	defer cm.watchersMu.Unlock()

	cm.watchers = append(cm.watchers, watcher)
	cm.logger.Debugf("Added configuration watcher (total: %d)", len(cm.watchers))
}

// RemoveWatcher removes a configuration watcher
func (cm *ConfigManager) RemoveWatcher(watcher ConfigWatcher) {
	cm.watchersMu.Lock()
	defer cm.watchersMu.Unlock()

	for i, w := range cm.watchers {
		if w == watcher {
			cm.watchers = append(cm.watchers[:i], cm.watchers[i+1:]...)
			cm.logger.Debugf("Removed configuration watcher (total: %d)", len(cm.watchers))
			return
		}
	}
}

// notifyWatchers notifies all watchers about configuration changes
func (cm *ConfigManager) notifyWatchers(oldConfig, newConfig *Config) error {
	cm.watchersMu.RLock()
	watchers := make([]ConfigWatcher, len(cm.watchers))
	copy(watchers, cm.watchers)
	cm.watchersMu.RUnlock()

	for _, watcher := range watchers {
		err := watcher.OnConfigUpdate(oldConfig, newConfig)
		if err != nil {
			cm.logger.Errorf("Configuration watcher notification failed: %v", err)
			return err
		}
	}

	return nil
}

// applyDefaults applies default values to the configuration
func (cm *ConfigManager) applyDefaults(config *Config) {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}

	if config.RetryInterval == 0 {
		config.RetryInterval = 1 * time.Second
	}

	if config.Transport == "" {
		config.Transport = TransportUDP
	}

	if config.FailoverTimeout == 0 {
		config.FailoverTimeout = 5 * time.Second
	}

	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}

	// Apply server defaults
	for i := range config.Servers {
		server := &config.Servers[i]
		if server.Port == 0 {
			// Default port (or use 2083 for TLS-enabled TCP connections)
			if config.TLSConfig != nil {
				server.Port = 2083 // RADSEC port
			} else {
				server.Port = 1812 // Standard RADIUS port
			}
		}

		if server.Timeout == 0 {
			server.Timeout = config.Timeout
		}

		if server.Priority == 0 {
			server.Priority = 1
		}

		if server.Weight == 0 {
			server.Weight = 1
		}
	}
}

// copyConfig creates a deep copy of the configuration
func (cm *ConfigManager) copyConfig(config *Config) *Config {
	if config == nil {
		return nil
	}

	// Create new config with basic fields
	newConfig := &Config{
		Servers:             make([]ServerConfig, len(config.Servers)),
		SharedSecret:        config.SharedSecret,
		Transport:           config.Transport,
		Timeout:             config.Timeout,
		MaxRetries:          config.MaxRetries,
		RetryInterval:       config.RetryInterval,
		FailoverTimeout:     config.FailoverTimeout,
		HealthCheckInterval: config.HealthCheckInterval,
		Logger:              config.Logger,
	}

	// Copy servers
	copy(newConfig.Servers, config.Servers)

	// Copy shared secret slice
	if len(config.SharedSecret) > 0 {
		newConfig.SharedSecret = make([]byte, len(config.SharedSecret))
		copy(newConfig.SharedSecret, config.SharedSecret)
	}

	return newConfig
}

// ConfigurationValidator provides configuration validation utilities
type ConfigurationValidator struct {
	logger log.Logger
}

// NewConfigurationValidator creates a new configuration validator
func NewConfigurationValidator(logger log.Logger) *ConfigurationValidator {
	if logger == nil {
		logger = log.NewDefaultLogger()
	}

	return &ConfigurationValidator{
		logger: logger,
	}
}

// ValidateAndFix validates and fixes common configuration issues
func (cv *ConfigurationValidator) ValidateAndFix(config *Config) error {
	if config == nil {
		return fmt.Errorf("configuration is nil")
	}

	// Validate servers
	if len(config.Servers) == 0 {
		return fmt.Errorf("at least one server must be configured")
	}

	for i, server := range config.Servers {
		if server.Address == "" {
			return fmt.Errorf("server %d: address is required", i)
		}

		if server.Port == 0 {
			// Fix: set default port
			if config.TLSConfig != nil {
				config.Servers[i].Port = 2083 // RADSEC port
			} else {
				config.Servers[i].Port = 1812 // Standard RADIUS port
			}
			cv.logger.Warnf("Server %d: port not specified, using default %d", i, config.Servers[i].Port)
		}

		if server.Priority == 0 {
			// Fix: set default priority
			config.Servers[i].Priority = 1
			cv.logger.Warnf("Server %d: priority not specified, using default 1", i)
		}

		if server.Weight == 0 {
			// Fix: set default weight
			config.Servers[i].Weight = 1
			cv.logger.Warnf("Server %d: weight not specified, using default 1", i)
		}

		if server.Timeout == 0 {
			// Fix: use global timeout
			config.Servers[i].Timeout = config.Timeout
			cv.logger.Warnf("Server %d: timeout not specified, using global timeout", i)
		}

		// MaxRetries is not a field in ServerConfig, so we skip this check

		// Validate shared secret
		if len(server.SharedSecret) == 0 && len(config.SharedSecret) == 0 {
			return fmt.Errorf("server %d: shared secret is required (either per-server or global)", i)
		}
	}

	// Validate global settings
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
		cv.logger.Warn("Global timeout not specified, using default 30 seconds")
	}

	if config.MaxRetries == 0 {
		config.MaxRetries = 3
		cv.logger.Warn("Global max retries not specified, using default 3")
	}

	if config.RetryInterval == 0 {
		config.RetryInterval = 1 * time.Second
		cv.logger.Warn("Global retry interval not specified, using default 1 second")
	}

	if config.Transport == "" {
		config.Transport = TransportUDP
		cv.logger.Warn("Transport not specified, using default UDP")
	}

	// Validate transport
	switch config.Transport {
	case TransportUDP, TransportTCP:
		// Valid
	default:
		return fmt.Errorf("invalid transport: %s", config.Transport)
	}

	// Validate failover settings
	if config.FailoverTimeout == 0 {
		config.FailoverTimeout = 5 * time.Second
		cv.logger.Warn("Failover timeout not specified, using default 5 seconds")
	}

	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
		cv.logger.Warn("Health check interval not specified, using default 30 seconds")
	}

	cv.logger.Info("Configuration validation completed successfully")
	return nil
}

// ConfigurationBuilder provides a fluent interface for building configurations
type ConfigurationBuilder struct {
	config *Config
}

// NewConfigurationBuilder creates a new configuration builder
func NewConfigurationBuilder() *ConfigurationBuilder {
	return &ConfigurationBuilder{
		config: &Config{
			Servers:             make([]ServerConfig, 0),
			Transport:           TransportUDP,
			Timeout:             30 * time.Second,
			MaxRetries:          3,
			RetryInterval:       1 * time.Second,
			FailoverTimeout:     5 * time.Second,
			HealthCheckInterval: 30 * time.Second,
		},
	}
}

// AddServer adds a server to the configuration
func (cb *ConfigurationBuilder) AddServer(address string, port int, sharedSecret string) *ConfigurationBuilder {
	server := ServerConfig{
		Address:      address,
		Port:         port,
		SharedSecret: []byte(sharedSecret),
		Priority:     1,
		Weight:       1,
		Timeout:      cb.config.Timeout,
	}

	cb.config.Servers = append(cb.config.Servers, server)
	return cb
}

// AddServerWithOptions adds a server with custom options
func (cb *ConfigurationBuilder) AddServerWithOptions(address string, port int, sharedSecret string, priority, weight int, timeout time.Duration) *ConfigurationBuilder {
	server := ServerConfig{
		Address:      address,
		Port:         port,
		SharedSecret: []byte(sharedSecret),
		Priority:     priority,
		Weight:       weight,
		Timeout:      timeout,
	}

	cb.config.Servers = append(cb.config.Servers, server)
	return cb
}

// WithGlobalSharedSecret sets the global shared secret
func (cb *ConfigurationBuilder) WithGlobalSharedSecret(secret string) *ConfigurationBuilder {
	cb.config.SharedSecret = []byte(secret)
	return cb
}

// WithTransport sets the transport type
func (cb *ConfigurationBuilder) WithTransport(transport TransportType) *ConfigurationBuilder {
	cb.config.Transport = transport
	return cb
}

// WithTimeout sets the global timeout
func (cb *ConfigurationBuilder) WithTimeout(timeout time.Duration) *ConfigurationBuilder {
	cb.config.Timeout = timeout
	return cb
}

// WithMaxRetries sets the global max retries
func (cb *ConfigurationBuilder) WithMaxRetries(maxRetries int) *ConfigurationBuilder {
	cb.config.MaxRetries = maxRetries
	return cb
}

// WithRetryInterval sets the retry interval
func (cb *ConfigurationBuilder) WithRetryInterval(interval time.Duration) *ConfigurationBuilder {
	cb.config.RetryInterval = interval
	return cb
}

// WithFailoverTimeout sets the failover timeout
func (cb *ConfigurationBuilder) WithFailoverTimeout(timeout time.Duration) *ConfigurationBuilder {
	cb.config.FailoverTimeout = timeout
	return cb
}

// WithHealthCheckInterval sets the health check interval
func (cb *ConfigurationBuilder) WithHealthCheckInterval(interval time.Duration) *ConfigurationBuilder {
	cb.config.HealthCheckInterval = interval
	return cb
}

// WithLogger sets the logger
func (cb *ConfigurationBuilder) WithLogger(logger log.Logger) *ConfigurationBuilder {
	cb.config.Logger = logger
	return cb
}

// Build builds the final configuration
func (cb *ConfigurationBuilder) Build() (*Config, error) {
	// Validate configuration
	err := validateConfig(cb.config)
	if err != nil {
		return nil, err
	}

	// Return a copy to prevent external modification
	return &Config{
		Servers:             append([]ServerConfig{}, cb.config.Servers...),
		SharedSecret:        append([]byte{}, cb.config.SharedSecret...),
		Transport:           cb.config.Transport,
		Timeout:             cb.config.Timeout,
		MaxRetries:          cb.config.MaxRetries,
		RetryInterval:       cb.config.RetryInterval,
		FailoverTimeout:     cb.config.FailoverTimeout,
		HealthCheckInterval: cb.config.HealthCheckInterval,
		Logger:              cb.config.Logger,
	}, nil
}

// ConfigTemplate provides common configuration templates
type ConfigTemplate struct{}

// NewConfigTemplate creates a new configuration template provider
func NewConfigTemplate() *ConfigTemplate {
	return &ConfigTemplate{}
}

// SingleServerUDP creates a single UDP server configuration
func (ct *ConfigTemplate) SingleServerUDP(address string, port int, sharedSecret string) *Config {
	return &Config{
		Servers: []ServerConfig{
			{
				Address:      address,
				Port:         port,
				SharedSecret: []byte(sharedSecret),
				Priority:     1,
				Weight:       1,
				Timeout:      30 * time.Second,
			},
		},
		Transport:           TransportUDP,
		Timeout:             30 * time.Second,
		MaxRetries:          3,
		RetryInterval:       1 * time.Second,
		FailoverTimeout:     5 * time.Second,
		HealthCheckInterval: 30 * time.Second,
	}
}

// MultiServerFailover creates a multi-server failover configuration
func (ct *ConfigTemplate) MultiServerFailover(servers []ServerConfig, sharedSecret string) *Config {
	config := &Config{
		Servers:             servers,
		SharedSecret:        []byte(sharedSecret),
		Transport:           TransportUDP,
		Timeout:             30 * time.Second,
		MaxRetries:          3,
		RetryInterval:       1 * time.Second,
		FailoverTimeout:     5 * time.Second,
		HealthCheckInterval: 30 * time.Second,
	}

	// Ensure servers have proper defaults
	for i := range config.Servers {
		if config.Servers[i].Priority == 0 {
			config.Servers[i].Priority = i + 1
		}
		if config.Servers[i].Weight == 0 {
			config.Servers[i].Weight = 1
		}
		if config.Servers[i].Timeout == 0 {
			config.Servers[i].Timeout = config.Timeout
		}
	}

	return config
}

// LoadBalancedCluster creates a load-balanced cluster configuration
func (ct *ConfigTemplate) LoadBalancedCluster(servers []ServerConfig, sharedSecret string) *Config {
	config := &Config{
		Servers:             servers,
		SharedSecret:        []byte(sharedSecret),
		Transport:           TransportUDP,
		Timeout:             30 * time.Second,
		MaxRetries:          3,
		RetryInterval:       1 * time.Second,
		FailoverTimeout:     5 * time.Second,
		HealthCheckInterval: 30 * time.Second,
	}

	// Ensure servers have proper defaults
	for i := range config.Servers {
		if config.Servers[i].Priority == 0 {
			config.Servers[i].Priority = 1
		}
		if config.Servers[i].Weight == 0 {
			config.Servers[i].Weight = 1
		}
		if config.Servers[i].Timeout == 0 {
			config.Servers[i].Timeout = config.Timeout
		}
	}

	return config
}

// RADSECCluster creates a RADSEC cluster configuration
func (ct *ConfigTemplate) RADSECCluster(servers []ServerConfig, sharedSecret string) *Config {
	config := &Config{
		Servers:             servers,
		SharedSecret:        []byte(sharedSecret),
		Transport:           TransportTCP,
		TLSConfig:           &tls.Config{},
		Timeout:             30 * time.Second,
		MaxRetries:          3,
		RetryInterval:       1 * time.Second,
		FailoverTimeout:     5 * time.Second,
		HealthCheckInterval: 30 * time.Second,
	}

	// Ensure servers have proper defaults for RADSEC
	for i := range config.Servers {
		if config.Servers[i].Port == 0 {
			config.Servers[i].Port = 2083
		}
		if config.Servers[i].Priority == 0 {
			config.Servers[i].Priority = 1
		}
		if config.Servers[i].Weight == 0 {
			config.Servers[i].Weight = 1
		}
		if config.Servers[i].Timeout == 0 {
			config.Servers[i].Timeout = config.Timeout
		}
	}

	return config
}
