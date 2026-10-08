package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// SCPCTIEvent mencatat aktivitas interaksi otentikasi honeypot SFTP
type SCPCTIEvent struct {
	Timestamp      string          `json:"timestamp"` // ISO 8601 UTC
	SensorID       string          `json:"sensor_id"`
	EventType      string          `json:"event_type"` // SFTP_LOGIN_SUCCESS, SFTP_AUTH_FAILED
	Status         string          `json:"status"`     // success, failed
	FailureReason  string          `json:"failure_reason,omitempty"`
	ClientIP       string          `json:"client_ip"`
	ClientPort     int             `json:"client_port"`
	Username       string          `json:"username"`
	Password       string          `json:"password"`
	ClientVersion  string          `json:"client_version,omitempty"`
	ParticipantNum int             `json:"participant_number,omitempty"`
	Mitre          MitreAttackInfo `json:"mitre_attack"`
}

type MitreAttackInfo struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	ID        string `json:"technique_id"`
}

type CTILogger struct {
	file *os.File
	mu   sync.Mutex
}

var ctiLogger *CTILogger

func initCTILogger(path string) (*CTILogger, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("gagal membuka log CTI %s: %w", path, err)
	}
	ctiLogger = &CTILogger{file: f}
	return ctiLogger, nil
}

func (l *CTILogger) Close() {
	if l != nil && l.file != nil {
		l.file.Close()
	}
}

func (l *CTILogger) LogEvent(event *SCPCTIEvent) {
	if l == nil || l.file == nil {
		return
	}
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[CTI] Gagal serialize JSON event: %v", err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.file.Write(append(data, '\n'))
}

func logCTIAuth(status, reason, clientIP string, clientPort int, username, password, clientVer string, participantNum int) {
	if ctiLogger == nil {
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "scp-honeypot"
	}

	eventType := "SFTP_AUTH_FAILED"
	technique := "Brute Force: Password Guessing"
	techniqueID := "T1110.001"

	if status == "success" {
		eventType = "SFTP_LOGIN_SUCCESS"
		technique = "Valid Accounts: Default/Known Accounts"
		techniqueID = "T1078"
	}

	event := &SCPCTIEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		SensorID:       hostname,
		EventType:      eventType,
		Status:         status,
		FailureReason:  reason,
		ClientIP:       clientIP,
		ClientPort:     clientPort,
		Username:       username,
		Password:       password,
		ClientVersion:  clientVer,
		ParticipantNum: participantNum,
		Mitre: MitreAttackInfo{
			Tactic:    "Initial Access",
			Technique: technique,
			ID:        techniqueID,
		},
	}

	ctiLogger.LogEvent(event)
}
