package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type UserInfo struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	IsBanned  bool      `json:"is_banned"`
	ScanCount int       `json:"scan_count"`
	LastScan  time.Time `json:"last_scan"`
}

type UsersManager struct {
	users map[int64]*UserInfo
	mu    sync.RWMutex
	path  string
}

var globalUsers *UsersManager

func InitUsersManager() error {
	globalUsers = &UsersManager{
		users: make(map[int64]*UserInfo),
		path:  "users.json",
	}
	return globalUsers.Load()
}

func (m *UsersManager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := os.Stat(m.path); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(m.path)
	if err != nil {
		return err
	}

	var list []*UserInfo
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	for _, u := range list {
		m.users[u.ID] = u
	}
	return nil
}

func (m *UsersManager) Save() error {
	m.mu.RLock()
	var list []*UserInfo
	for _, u := range m.users {
		list = append(list, u)
	}
	m.mu.RUnlock()

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.path, data, 0644)
}

func (m *UsersManager) GetUser(id int64) (*UserInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if ok {
		// Return a copy to prevent external modification issues
		copyU := *u
		return &copyU, true
	}
	return nil, false
}

func (m *UsersManager) RegisterOrUpdateUser(id int64, username, firstName, lastName string) *UserInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	u, ok := m.users[id]
	if !ok {
		u = &UserInfo{
			ID:        id,
			Username:  username,
			FirstName: firstName,
			LastName:  lastName,
		}
		m.users[id] = u
	} else {
		u.Username = username
		u.FirstName = firstName
		u.LastName = lastName
	}

	_ = m.saveNoLock()
	return u
}

func (m *UsersManager) RecordScan(id int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if u, ok := m.users[id]; ok {
		u.ScanCount++
		u.LastScan = time.Now()
		_ = m.saveNoLock()
	}
}

func (m *UsersManager) SetBanned(id int64, banned bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if u, ok := m.users[id]; ok {
		u.IsBanned = banned
		_ = m.saveNoLock()
		return true
	}
	return false
}

func (m *UsersManager) GetAllUsers() []*UserInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var list []*UserInfo
	for _, u := range m.users {
		copyU := *u
		list = append(list, &copyU)
	}
	return list
}

func (m *UsersManager) saveNoLock() error {
	var list []*UserInfo
	for _, u := range m.users {
		list = append(list, u)
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.path, data, 0644)
}
