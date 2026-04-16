package echo

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Port int
}

func LoadConfig() (Config, error) {
	cfg := Config{
		Port: 8443,
	}

	if v := os.Getenv("PORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("PORT: %w", err)
		}
		if port < 1 || port > 65535 {
			return Config{}, fmt.Errorf("PORT: %d out of range [1, 65535]", port)
		}
		cfg.Port = port
	}

	return cfg, nil
}
