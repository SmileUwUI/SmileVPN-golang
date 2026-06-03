package main

import (
	"SmileVPN/client"
	"SmileVPN/internal/logger"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var (
		usernameString     string
		passwordString     string
		initPasswordString string
		host               string
		hostName           string
		port               int
		loggerLevel        int
		updateThroughSalt  bool
		batching           bool
	)

	flag.StringVar(&usernameString, "u", "", "Hex username (short)")
	flag.StringVar(&usernameString, "username", "", "Hex username")

	flag.StringVar(&passwordString, "p", "", "Hex password (short)")
	flag.StringVar(&passwordString, "password", "", "Hex password")

	flag.StringVar(&initPasswordString, "i", "", "Hex initialization password (short)")
	flag.StringVar(&initPasswordString, "init-password", "", "Hex initialization password")

	flag.BoolVar(&updateThroughSalt, "U", false, "Update keys through salt (short)")
	flag.BoolVar(&updateThroughSalt, "update-through-salt", false, "Update keys through salt")

	flag.BoolVar(&updateThroughSalt, "b", false, " Group the packages into batches (short)")
	flag.BoolVar(&updateThroughSalt, "batching", false, " Group the packages into batches")

	flag.StringVar(&host, "h", "", "Host (short)")
	flag.StringVar(&host, "host", "", "Host")

	flag.StringVar(&hostName, "H", "", "Host name (short)")
	flag.StringVar(&hostName, "host-name", "", "Host name")

	flag.IntVar(&port, "P", 16020, "Port (short)")
	flag.IntVar(&port, "port", 16020, "Port")

	flag.IntVar(&loggerLevel, "l", 2, "Log level (short)")
	flag.IntVar(&loggerLevel, "log-level", 2, "Log level")

	flag.Parse()

	if usernameString != "" && !isValidHex(usernameString) {
		fmt.Fprintln(os.Stderr, "Error: Invalid hex format for username. Expected hexadecimal string (0-9, a-f, A-F)")
		flag.Usage()
		os.Exit(1)
	}

	if passwordString != "" && !isValidHex(passwordString) {
		fmt.Fprintln(os.Stderr, "Error: Invalid hex format for password. Expected hexadecimal string (0-9, a-f, A-F)")
		flag.Usage()
		os.Exit(1)
	}

	if initPasswordString != "" && !isValidHex(initPasswordString) {
		fmt.Fprintln(os.Stderr, "Error: Invalid hex format for initialization password. Expected hexadecimal string (0-9, a-f, A-F)")
		flag.Usage()
		os.Exit(1)
	}

	if usernameString != "" && len(usernameString) != 32 {
		fmt.Fprintf(os.Stderr, "Error: Invalid username length. Expected 32 hex characters (16 bytes), got %d\n", len(usernameString))
		flag.Usage()
		os.Exit(1)
	}

	if passwordString != "" && len(passwordString) != 32 {
		fmt.Fprintf(os.Stderr, "Error: Invalid password length. Expected 32 hex characters (16 bytes), got %d\n", len(passwordString))
		flag.Usage()
		os.Exit(1)
	}

	if initPasswordString != "" && len(initPasswordString) != 64 {
		fmt.Fprintf(os.Stderr, "Error: Invalid initialization password length. Expected 64 hex characters (32 bytes), got %d\n", len(initPasswordString))
		flag.Usage()
		os.Exit(1)
	}

	if host == "" {
		fmt.Fprintln(os.Stderr, "Error: Host is required. Please provide a host using -h or --host")
		flag.Usage()
		os.Exit(1)
	}

	if port < 1 || port > 65535 {
		fmt.Fprintf(os.Stderr, "Error: Invalid port number %d. Port must be between 1 and 65535\n", port)
		flag.Usage()
		os.Exit(1)
	}

	if loggerLevel < 1 || loggerLevel > 4 {
		fmt.Fprintf(os.Stderr, "Error: Invalid log level %d. Log level must be between 0 and 5\n", loggerLevel)
		fmt.Fprintln(os.Stderr, "1: ERROR, 2: INFO, 3: DEBUG, 4: TRACE")
		flag.Usage()
		os.Exit(1)
	}

	var username, password, initPassword []byte
	var err error

	if usernameString != "" {
		username, err = hex.DecodeString(usernameString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to decode username: %v\n", err)
			os.Exit(1)
		}
	} else {
		username = make([]byte, 16)
	}

	if passwordString != "" {
		password, err = hex.DecodeString(passwordString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to decode password: %v\n", err)
			os.Exit(1)
		}
	} else {
		password = make([]byte, 16)
	}

	if initPasswordString != "" {
		initPassword, err = hex.DecodeString(initPasswordString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to decode initialization password: %v\n", err)
			os.Exit(1)
		}
	} else {
		initPassword = make([]byte, 32)
	}

	var initPasswordArray [32]byte
	var usernameArray [16]byte
	var passwordArray [16]byte

	copy(initPasswordArray[:], initPassword)
	copy(usernameArray[:], username)
	copy(passwordArray[:], password)

	log := logger.NewLogger(loggerLevel)

	clientInstance, err := client.NewClient(host, hostName, port, initPasswordArray, usernameArray, passwordArray, updateThroughSalt, batching, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to create client: %v\n", err)
		os.Exit(1)
	}

	err = clientInstance.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Client run error: %v", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP,
		syscall.SIGABRT,
	)

	<-sigChan
	clientInstance.Stop()
}

func isValidHex(s string) bool {
	if s == "" {
		return true
	}

	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
