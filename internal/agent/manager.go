package agent

import (
	"sync"
)

var (
	connectionManager = &ConnectionManager{
		connections: make(map[uint]*ClientConnection),
	}
)

type ConnectionManager struct {
	mu          sync.RWMutex
	connections map[uint]*ClientConnection
}

func GetConnectionManager() *ConnectionManager {
	return connectionManager
}

func (cm *ConnectionManager) Register(clientID uint, cc *ClientConnection) {
	cm.mu.Lock()
	cm.connections[clientID] = cc
	cm.mu.Unlock()
}

func (cm *ConnectionManager) Unregister(clientID uint) {
	cm.mu.Lock()
	delete(cm.connections, clientID)
	cm.mu.Unlock()
}

func (cm *ConnectionManager) Get(clientID uint) (*ClientConnection, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	cc, ok := cm.connections[clientID]
	return cc, ok
}

func (cm *ConnectionManager) SendDisconnect(clientID uint) bool {
	cm.mu.RLock()
	cc, ok := cm.connections[clientID]
	cm.mu.RUnlock()

	if !ok {
		return false
	}

	err := cc.SendDisconnect()
	return err == nil
}

func (cm *ConnectionManager) SendCommand(clientID uint, cmdType string, cmdID string, payload map[string]interface{}) bool {
	cm.mu.RLock()
	cc, ok := cm.connections[clientID]
	cm.mu.RUnlock()

	if !ok {
		return false
	}

	return cc.SendCommand(cmdType, cmdID, payload) == nil
}
