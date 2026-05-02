package users

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

type User struct {
	mu       sync.RWMutex
	username [16]byte
	password [16]byte
}

func (u *User) GetUsername() (username [16]byte) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.username
}

func (u *User) GetPassword() (password [16]byte) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.password
}

type Users struct {
	mu    sync.RWMutex
	users map[[16]byte]*User
	path  string
}

func FromFile(path string) (users *Users, err error) {
	users = &Users{
		users: make(map[[16]byte]*User),
		path:  path,
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return users, nil
	} else if err != nil {
		return nil, err
	}

	usersFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read users file: %w", err)
	}

	usersLines := strings.Split(string(usersFile), "\n")

	for index, line := range usersLines {
		credentials := strings.Split(line, " ")
		if len(credentials) != 2 {
			return nil, fmt.Errorf("users parsing error: invalid format on line %d", index+1)
		}

		if len(credentials[0]) != 32 {
			return nil, fmt.Errorf("users parsing error: invalid format (username) on line %d", index+1)
		}

		if len(credentials[1]) != 32 {
			return nil, fmt.Errorf("users parsing error: invalid format (password) on line %d", index+1)
		}

		usernameBytes, err := hex.DecodeString(credentials[0])
		if err != nil {
			return nil, fmt.Errorf("users parsing error: error parsing username on line %d (%w)", index+1, err)
		}

		passwordBytes, err := hex.DecodeString(credentials[1])
		if err != nil {
			return nil, fmt.Errorf("users parsing error: error parsing password on line %d (%w)", index+1, err)
		}

		var username [16]byte
		var password [16]byte
		copy(username[:], usernameBytes)
		copy(password[:], passwordBytes)

		users.AddUser(username, password)
	}

	return users, nil
}

func (u *Users) AddUser(username, password [16]byte) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.users[username] = &User{
		username: username,
		password: password,
	}
}

func (u *Users) Save() (err error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	var lines []string

	for username, user := range u.users {
		userPassword := user.GetPassword()
		line := fmt.Sprintf("%s %s",
			hex.EncodeToString(username[:]),
			hex.EncodeToString(userPassword[:]))
		lines = append(lines, line)
	}

	content := strings.Join(lines, "\n")
	if err := os.WriteFile(u.path, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to save users file: %w", err)
	}

	return nil
}

func (u *Users) GetUser(username [16]byte) (user *User) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	user, ok := u.users[username]

	if !ok {
		return nil
	}

	return user
}
