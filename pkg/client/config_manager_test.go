package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestNewConfigManager(t *testing.T) {
	manager := NewConfigManager("test.yaml", nil)

	assert.NotNil(t, manager)
	assert.Equal(t, "test.yaml", manager.configFile)
	assert.NotNil(t, manager.logger)
	assert.Equal(t, 5*time.Second, manager.checkInterval)
	assert.NotNil(t, manager.watchers)
	assert.NotNil(t, manager.updateChan)
	assert.NotNil(t, manager.stopChan)
}

func TestConfigManager_LoadConfig_DefaultConfig(t *testing.T) {
	manager := NewConfigManager("", nil)

	config, err := manager.LoadConfig()

	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, TransportUDP, config.Transport)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, 5*time.Second, config.FailoverTimeout)
	assert.Equal(t, 30*time.Second, config.HealthCheckInterval)
}

func TestConfigManager_LoadConfig_CreateFile(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test_config.yaml")

	manager := NewConfigManager(configFile, nil)

	config, err := manager.LoadConfig()

	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Check that file was created
	_, err = os.Stat(configFile)
	assert.NoError(t, err)
}

func TestConfigManager_LoadConfig_ExistingFile(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "existing_config.yaml")

	// Create a test configuration file
	testConfig := &Config{
		Servers: []ServerConfig{
			{
				Address:      "192.168.1.100",
				Port:         1812,
				SharedSecret: []byte("test_secret"),
				Priority:     1,
				Weight:       1,
				Timeout:      20 * time.Second,
			},
		},
		Transport:           TransportTCP,
		Timeout:             20 * time.Second,
		MaxRetries:          2,
		FailoverTimeout:     3 * time.Second,
		HealthCheckInterval: 20 * time.Second,
	}

	data, err := yaml.Marshal(testConfig)
	assert.NoError(t, err)

	err = os.WriteFile(configFile, data, 0644)
	assert.NoError(t, err)

	manager := NewConfigManager(configFile, nil)

	config, err := manager.LoadConfig()

	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, TransportTCP, config.Transport)
	assert.Equal(t, 20*time.Second, config.Timeout)
	assert.Equal(t, 2, config.MaxRetries)
	assert.Equal(t, 3*time.Second, config.FailoverTimeout)
	assert.Equal(t, 20*time.Second, config.HealthCheckInterval)
	assert.Len(t, config.Servers, 1)
	assert.Equal(t, "192.168.1.100", config.Servers[0].Address)
	assert.Equal(t, 1812, config.Servers[0].Port)
}

func TestConfigManager_SaveConfig(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "save_config.yaml")

	manager := NewConfigManager(configFile, nil)

	config := &Config{
		Servers: []ServerConfig{
			{
				Address:      "10.0.0.1",
				Port:         1812,
				SharedSecret: []byte("save_secret"),
				Priority:     1,
				Weight:       1,
				Timeout:      25 * time.Second,
			},
		},
		Transport:           TransportUDP,
		Timeout:             25 * time.Second,
		MaxRetries:          4,
		FailoverTimeout:     6 * time.Second,
		HealthCheckInterval: 35 * time.Second,
	}

	err := manager.SaveConfig(config)
	assert.NoError(t, err)

	// Verify file was created and contains expected data
	data, err := os.ReadFile(configFile)
	assert.NoError(t, err)

	var savedConfig Config
	err = yaml.Unmarshal(data, &savedConfig)
	assert.NoError(t, err)

	assert.Equal(t, config.Transport, savedConfig.Transport)
	assert.Equal(t, config.Timeout, savedConfig.Timeout)
	assert.Equal(t, config.MaxRetries, savedConfig.MaxRetries)
	assert.Equal(t, config.FailoverTimeout, savedConfig.FailoverTimeout)
	assert.Equal(t, config.HealthCheckInterval, savedConfig.HealthCheckInterval)
	assert.Len(t, savedConfig.Servers, 1)
	assert.Equal(t, "10.0.0.1", savedConfig.Servers[0].Address)
}

func TestConfigManager_SaveConfig_NoFile(t *testing.T) {
	manager := NewConfigManager("", nil)

	config := DefaultConfig()

	err := manager.SaveConfig(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no configuration file specified")
}

func TestConfigManager_GetConfig(t *testing.T) {
	manager := NewConfigManager("", nil)

	// Load default config first
	_, err := manager.LoadConfig()
	assert.NoError(t, err)

	config := manager.GetConfig()

	assert.NotNil(t, config)
	assert.Equal(t, TransportUDP, config.Transport)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 3, config.MaxRetries)
}

func TestConfigManager_GetConfig_NoConfigLoaded(t *testing.T) {
	manager := NewConfigManager("", nil)

	config := manager.GetConfig()

	assert.NotNil(t, config)
	// Should return default config
	assert.Equal(t, TransportUDP, config.Transport)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 3, config.MaxRetries)
}

func TestConfigManager_UpdateConfig(t *testing.T) {
	manager := NewConfigManager("", nil)

	// Load initial config
	_, err := manager.LoadConfig()
	assert.NoError(t, err)

	// Update with new config
	newConfig := &Config{
		Servers: []ServerConfig{
			{
				Address:      "192.168.1.200",
				Port:         1812,
				SharedSecret: []byte("updated_secret"),
				Priority:     1,
				Weight:       1,
				Timeout:      40 * time.Second,
			},
		},
		Transport:           TransportTCP,
		Timeout:             40 * time.Second,
		MaxRetries:          5,
		FailoverTimeout:     10 * time.Second,
		HealthCheckInterval: 60 * time.Second,
	}

	err = manager.UpdateConfig(newConfig)
	assert.NoError(t, err)

	// Verify config was updated
	currentConfig := manager.GetConfig()
	assert.Equal(t, TransportTCP, currentConfig.Transport)
	assert.Equal(t, 40*time.Second, currentConfig.Timeout)
	assert.Equal(t, 5, currentConfig.MaxRetries)
	assert.Equal(t, 10*time.Second, currentConfig.FailoverTimeout)
	assert.Equal(t, 60*time.Second, currentConfig.HealthCheckInterval)
}

func TestConfigManager_UpdateConfig_ValidationFails(t *testing.T) {
	manager := NewConfigManager("", nil)

	// Try to update with invalid config (no servers)
	invalidConfig := &Config{
		Servers:    []ServerConfig{},
		Transport:  TransportUDP,
		Timeout:    30 * time.Second,
		MaxRetries: 3,
	}

	err := manager.UpdateConfig(invalidConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration validation failed")
}

func TestConfigManager_StartWatching(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "watch_config.yaml")

	// Create initial config file
	initialConfig := DefaultConfig()
	initialConfig.Servers = []ServerConfig{
		{
			Address:      "127.0.0.1",
			Port:         1812,
			SharedSecret: []byte("testing123"),
			Priority:     1,
			Weight:       1,
			Timeout:      5 * time.Second,
		},
	}
	data, err := yaml.Marshal(initialConfig)
	assert.NoError(t, err)
	err = os.WriteFile(configFile, data, 0644)
	assert.NoError(t, err)

	manager := NewConfigManager(configFile, nil)

	// Load initial config
	_, err = manager.LoadConfig()
	assert.NoError(t, err)

	// Start watching in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manager.StartWatching(ctx)

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Modify config file
	modifiedConfig := *initialConfig
	modifiedConfig.Timeout = 60 * time.Second

	modifiedData, err := yaml.Marshal(&modifiedConfig)
	assert.NoError(t, err)

	err = os.WriteFile(configFile, modifiedData, 0644)
	assert.NoError(t, err)

	// Wait for file change detection
	time.Sleep(6 * time.Second) // checkInterval is 5 seconds + buffer

	// Verify config was reloaded
	currentConfig := manager.GetConfig()
	assert.Equal(t, 60*time.Second, currentConfig.Timeout)

	// Stop watching
	cancel()
}

func TestConfigManager_StartWatching_NoFile(_ *testing.T) {
	manager := NewConfigManager("", nil)

	// Should not panic or error when no file specified
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	manager.StartWatching(ctx)
	// Should return quickly without error
}

func TestConfigManager_StopWatching(_ *testing.T) {
	manager := NewConfigManager("", nil)

	// Should not panic
	manager.StopWatching()
}

type MockConfigWatcher struct {
	updateCalled bool
	oldConfig    *Config
	newConfig    *Config
}

func (m *MockConfigWatcher) OnConfigUpdate(oldConfig, newConfig *Config) error {
	m.updateCalled = true
	m.oldConfig = oldConfig
	m.newConfig = newConfig
	return nil
}

func TestConfigManager_AddWatcher(t *testing.T) {
	manager := NewConfigManager("", nil)

	watcher := &MockConfigWatcher{}
	manager.AddWatcher(watcher)

	// Load initial config
	_, err := manager.LoadConfig()
	assert.NoError(t, err)

	// Update config to trigger watcher
	newConfig := DefaultConfig()
	newConfig.Servers = []ServerConfig{
		{
			Address:      "127.0.0.1",
			Port:         1812,
			SharedSecret: []byte("testing123"),
			Priority:     1,
			Weight:       1,
			Timeout:      5 * time.Second,
		},
	}
	newConfig.Timeout = 45 * time.Second

	err = manager.UpdateConfig(newConfig)
	assert.NoError(t, err)

	// Verify watcher was called
	assert.True(t, watcher.updateCalled)
	assert.NotNil(t, watcher.oldConfig)
	assert.NotNil(t, watcher.newConfig)
	assert.Equal(t, 45*time.Second, watcher.newConfig.Timeout)
}

func TestConfigManager_RemoveWatcher(t *testing.T) {
	manager := NewConfigManager("", nil)

	watcher := &MockConfigWatcher{}
	manager.AddWatcher(watcher)
	manager.RemoveWatcher(watcher)

	// Load initial config
	_, err := manager.LoadConfig()
	assert.NoError(t, err)

	// Update config
	newConfig := DefaultConfig()
	newConfig.Servers = []ServerConfig{
		{
			Address:      "127.0.0.1",
			Port:         1812,
			SharedSecret: []byte("testing123"),
			Priority:     1,
			Weight:       1,
			Timeout:      5 * time.Second,
		},
	}
	newConfig.Timeout = 45 * time.Second

	err = manager.UpdateConfig(newConfig)
	assert.NoError(t, err)

	// Verify watcher was not called
	assert.False(t, watcher.updateCalled)
}

func TestConfigurationValidator_ValidateAndFix(t *testing.T) {
	validator := NewConfigurationValidator(nil)

	// Test with incomplete config
	config := &Config{
		Servers: []ServerConfig{
			{
				Address:      "192.168.1.1",
				SharedSecret: []byte("testing123"),
				// Missing port, priority, weight, timeout, maxRetries
			},
		},
		// Missing global settings
	}

	err := validator.ValidateAndFix(config)
	assert.NoError(t, err)

	// Verify defaults were applied
	assert.Equal(t, 1812, config.Servers[0].Port)
	assert.Equal(t, 1, config.Servers[0].Priority)
	assert.Equal(t, 1, config.Servers[0].Weight)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, TransportUDP, config.Transport)
}

func TestConfigurationValidator_ValidateAndFix_NoServers(t *testing.T) {
	validator := NewConfigurationValidator(nil)

	config := &Config{
		Servers: []ServerConfig{},
	}

	err := validator.ValidateAndFix(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one server must be configured")
}

func TestConfigurationValidator_ValidateAndFix_InvalidTransport(t *testing.T) {
	validator := NewConfigurationValidator(nil)

	config := &Config{
		Servers: []ServerConfig{
			{
				Address:      "192.168.1.1",
				Port:         1812,
				SharedSecret: []byte("secret"),
			},
		},
		Transport: "invalid",
	}

	err := validator.ValidateAndFix(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transport")
}

func TestConfigurationBuilder_Build(t *testing.T) {
	builder := NewConfigurationBuilder()

	config, err := builder.
		AddServer("192.168.1.1", 1812, "secret1").
		AddServer("192.168.1.2", 1812, "secret2").
		WithGlobalSharedSecret("global_secret").
		WithTransport(TransportTCP).
		WithTimeout(45 * time.Second).
		WithMaxRetries(5).
		WithFailoverTimeout(10 * time.Second).
		WithHealthCheckInterval(60 * time.Second).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Len(t, config.Servers, 2)
	assert.Equal(t, "192.168.1.1", config.Servers[0].Address)
	assert.Equal(t, "192.168.1.2", config.Servers[1].Address)
	assert.Equal(t, []byte("global_secret"), config.SharedSecret)
	assert.Equal(t, TransportTCP, config.Transport)
	assert.Equal(t, 45*time.Second, config.Timeout)
	assert.Equal(t, 5, config.MaxRetries)
	assert.Equal(t, 10*time.Second, config.FailoverTimeout)
	assert.Equal(t, 60*time.Second, config.HealthCheckInterval)
}

func TestConfigurationBuilder_AddServerWithOptions(t *testing.T) {
	builder := NewConfigurationBuilder()

	config, err := builder.
		AddServerWithOptions("192.168.1.1", 1812, "secret", 2, 3, 20*time.Second).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Len(t, config.Servers, 1)
	assert.Equal(t, "192.168.1.1", config.Servers[0].Address)
	assert.Equal(t, 1812, config.Servers[0].Port)
	assert.Equal(t, []byte("secret"), config.Servers[0].SharedSecret)
	assert.Equal(t, 2, config.Servers[0].Priority)
	assert.Equal(t, 3, config.Servers[0].Weight)
	assert.Equal(t, 20*time.Second, config.Servers[0].Timeout)
}

func TestConfigTemplate_SingleServerUDP(t *testing.T) {
	template := NewConfigTemplate()

	config := template.SingleServerUDP("192.168.1.1", 1812, "secret")

	assert.NotNil(t, config)
	assert.Len(t, config.Servers, 1)
	assert.Equal(t, "192.168.1.1", config.Servers[0].Address)
	assert.Equal(t, 1812, config.Servers[0].Port)
	assert.Equal(t, []byte("secret"), config.Servers[0].SharedSecret)
	assert.Equal(t, TransportUDP, config.Transport)
}

func TestConfigTemplate_MultiServerFailover(t *testing.T) {
	template := NewConfigTemplate()

	servers := []ServerConfig{
		{Address: "192.168.1.1", Port: 1812},
		{Address: "192.168.1.2", Port: 1812},
	}

	config := template.MultiServerFailover(servers, "shared_secret")

	assert.NotNil(t, config)
	assert.Len(t, config.Servers, 2)
	assert.Equal(t, []byte("shared_secret"), config.SharedSecret)
	assert.Equal(t, TransportUDP, config.Transport)

	// Verify server defaults were applied
	assert.Equal(t, 1, config.Servers[0].Priority)
	assert.Equal(t, 2, config.Servers[1].Priority)
	assert.Equal(t, 1, config.Servers[0].Weight)
	assert.Equal(t, 1, config.Servers[1].Weight)
}

func TestConfigTemplate_LoadBalancedCluster(t *testing.T) {
	template := NewConfigTemplate()

	servers := []ServerConfig{
		{Address: "192.168.1.1", Port: 1812},
		{Address: "192.168.1.2", Port: 1812},
		{Address: "192.168.1.3", Port: 1812},
	}

	config := template.LoadBalancedCluster(servers, "cluster_secret")

	assert.NotNil(t, config)
	assert.Len(t, config.Servers, 3)
	assert.Equal(t, []byte("cluster_secret"), config.SharedSecret)
	assert.Equal(t, TransportUDP, config.Transport)

	// Verify all servers have same priority for load balancing
	for _, server := range config.Servers {
		assert.Equal(t, 1, server.Priority)
		assert.Equal(t, 1, server.Weight)
	}
}

func TestConfigTemplate_RADSECCluster(t *testing.T) {
	template := NewConfigTemplate()

	servers := []ServerConfig{
		{Address: "radsec1.example.com"},
		{Address: "radsec2.example.com"},
	}

	config := template.RADSECCluster(servers, "radsec_secret")

	assert.NotNil(t, config)
	assert.Len(t, config.Servers, 2)
	assert.Equal(t, []byte("radsec_secret"), config.SharedSecret)
	assert.Equal(t, TransportTCP, config.Transport)
	assert.NotNil(t, config.TLSConfig) // Should have TLS config for RADSEC

	// Verify RADSEC default port was set
	for _, server := range config.Servers {
		assert.Equal(t, 2083, server.Port)
	}
}

// Benchmark tests
func BenchmarkConfigManager_LoadConfig(b *testing.B) {
	manager := NewConfigManager("", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.LoadConfig()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConfigManager_GetConfig(b *testing.B) {
	manager := NewConfigManager("", nil)
	_, err := manager.LoadConfig()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.GetConfig()
	}
}

func BenchmarkConfigurationBuilder_Build(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder := NewConfigurationBuilder()
		_, err := builder.
			AddServer("192.168.1.1", 1812, "secret").
			WithTransport(TransportUDP).
			WithTimeout(30 * time.Second).
			Build()
		if err != nil {
			b.Fatal(err)
		}
	}
}
