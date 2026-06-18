package main

import (
	"encoding/json"
	"os"
	"strconv"
	"sync"
)

type Config struct {
	TelegramBotToken string `json:"telegram_bot_token"`
	TelegramAdminID  int64  `json:"telegram_admin_id"`
	ShodanAPIKey     string `json:"shodan_api_key"`
	BotEnabled       bool   `json:"bot_enabled"`
}

var (
	globalConfig Config
	configMu     sync.RWMutex
	configPath   = "config.json"
)

func LoadConfig() error {
	configMu.Lock()
	defer configMu.Unlock()

	// Default values
	globalConfig = Config{
		ShodanAPIKey: "aCfjD5pzHZv60uzUXbdNf4SCTExJUt0s",
		BotEnabled:   true,
	}

	// Read config file if exists
	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err == nil {
			var cfg Config
			if err := json.Unmarshal(data, &cfg); err == nil {
				globalConfig = cfg
			}
		}
	}

	// Override with env variables if set
	if envToken := os.Getenv("TELEGRAM_BOT_TOKEN"); envToken != "" {
		globalConfig.TelegramBotToken = envToken
	}
	if envAdminID := os.Getenv("TELEGRAM_ADMIN_ID"); envAdminID != "" {
		if id, err := strconv.ParseInt(envAdminID, 10, 64); err == nil {
			globalConfig.TelegramAdminID = id
		}
	}
	if envShodan := os.Getenv("SHODAN_API_KEY"); envShodan != "" {
		globalConfig.ShodanAPIKey = envShodan
	}

	// Save config (creates config.json if not present)
	return saveConfigNoLock()
}

func GetConfig() Config {
	configMu.RLock()
	defer configMu.RUnlock()
	return globalConfig
}

func UpdateBotEnabled(enabled bool) error {
	configMu.Lock()
	defer configMu.Unlock()
	globalConfig.BotEnabled = enabled
	return saveConfigNoLock()
}

func saveConfigNoLock() error {
	data, err := json.MarshalIndent(globalConfig, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}
