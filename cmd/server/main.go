package main

import (
	"SmileVPN/internal/logger"
	"SmileVPN/server"
	"SmileVPN/server/config"
	"SmileVPN/server/users"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var (
		configPath string
		logLevel   int
	)

	flag.StringVar(&configPath, "c", "", "Path to configuration file (short)")
	flag.StringVar(&configPath, "config", "", "Path to configuration file")

	flag.IntVar(&logLevel, "l", 2, "Log level (short): 1=ERROR, 2=INFO, 3=DEBUG, 4=TRACE")
	flag.IntVar(&logLevel, "log-level", 2, "Log level: 1=ERROR, 2=INFO, 3=DEBUG, 4=TRACE")
	flag.Parse()

	if logLevel < 1 || logLevel > 4 {
		fmt.Printf("Error: invalid log level %d. Must be between 1 and 4\n", logLevel)
		flag.Usage()
		os.Exit(1)
	}

	configInstance, err := config.FromFile(configPath)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	usersInstance, err := users.FromFile(configInstance.UsersPath)
	if err != nil {
		fmt.Printf("Error loading users: %v\n", err)
		os.Exit(1)
	}

	logger := logger.NewLogger(logLevel)

	serverInstance, err := server.NewServer(configInstance, usersInstance, logger)
	if err != nil {
		logger.Error("Failed to create server: %v", err)
		os.Exit(1)
	}

	err = serverInstance.Start()
	if err != nil {
		logger.Error("Failed to start server: %v", err)
		os.Exit(1)
	}

	logger.Info("Server started successfully. Press Ctrl+C to stop")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP,
		syscall.SIGABRT,
	)
	<-sigChan

}
