package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	MaxClients   int      `json:"max_clients"`
	InitPassword [32]byte `json:"init_password"`
	UsersPath    string   `json:"users_path"`
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type Alias Config
	aux := &struct {
		InitPassword string `json:"init_password"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.InitPassword != "" {
		decoded, err := hex.DecodeString(aux.InitPassword)
		if err != nil {
			return fmt.Errorf("failed to decode init_password as hex: %w", err)
		}
		if len(decoded) != 32 {
			return fmt.Errorf("init_password must be 32 bytes, got %d bytes", len(decoded))
		}
		copy(c.InitPassword[:], decoded)
	}

	return nil
}

func FromFile(path string) (config *Config, err error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		defaultConfig := DefaultConfig()
		return defaultConfig, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var configRef Config
	if err := json.Unmarshal(data, &configRef); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	if err := configRef.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &configRef, nil
}

func DefaultConfig() (config *Config) {
	defaultPassword := sha256.Sum256([]byte("password"))

	return &Config{
		Host:         "0.0.0.0",
		Port:         16020,
		MaxClients:   128,
		InitPassword: defaultPassword,
		UsersPath:    "./users.json",
	}
}

func (c *Config) Validate() (err error) {
	if c.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", c.Port)
	}

	if c.MaxClients < 1 {
		return fmt.Errorf("max_clients must be at least 1, got %d", c.MaxClients)
	}

	if c.UsersPath == "" {
		return fmt.Errorf("users_path cannot be empty")
	}

	return nil
}
