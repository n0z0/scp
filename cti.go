package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// SCPCTIEvent mencatat aktivitas interaksi otentikasi honeypot SFTP dan manipulasi file
type SCPCTIEvent struct {
	Timestamp      string          `json:"timestamp"` // ISO 8601 UTC
	SensorID       string          `json:"sensor_id"`
	EventType      string          `json:"event_type"` // SFTP_LOGIN_SUCCESS, SFTP_AUTH_FAILED, SFTP_FILE_ACTIVITY
	Status         string          `json:"status"`     // success, failed
	FailureReason  string          `json:"failure_reason,omitempty"`
	ClientIP       string          `json:"client_ip"`
	ClientPort     int             `json:"client_port"`
	Username       string          `json:"username"`
	Password       string          `json:"password,omitempty"`
	ClientVersion  string          `json:"client_version,omitempty"`
	ParticipantNum int             `json:"participant_number,omitempty"`
	FileActivity   *FileActivity   `json:"file_activity,omitempty"`
	Mitre          MitreAttackInfo `json:"mitre_attack"`
}

type FileActivity struct {
	Action string `json:"action"` // UPLOAD, DOWNLOAD, LIST_DIR, STAT, DELETE, RENAME, MKDIR, RMDIR
	Path   string `json:"path"`
	Target string `json:"target_path,omitempty"` // untuk rename/symlink
	Size   int64  `json:"size_bytes,omitempty"`
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

func logCTIFileActivity(clientIP string, clientPort int, username, clientVer string, participantNum int, action, path, target string, size int64, status, reason string) {
	if ctiLogger == nil {
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "scp-honeypot"
	}

	tactic := "Execution"
	technique := "File and Directory Discovery"
	techniqueID := "T1083"

	switch action {
	case "LIST_DIR", "STAT", "READLINK":
		tactic = "Discovery"
		technique = "File and Directory Discovery"
		techniqueID = "T1083"
	case "UPLOAD":
		tactic = "Persistence"
		technique = "Upload Malware / Tools"
		techniqueID = "T1105" // Ingress Tool Transfer
	case "DOWNLOAD":
		tactic = "Exfiltration"
		technique = "Data from Local System"
		techniqueID = "T1005"
	case "DELETE", "RMDIR":
		tactic = "Impact"
		technique = "Data Destruction"
		techniqueID = "T1485"
	case "RENAME", "MKDIR":
		tactic = "Defense Evasion"
		technique = "Masquerading / File Modification"
		techniqueID = "T1036"
	}

	event := &SCPCTIEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		SensorID:       hostname,
		EventType:      "SFTP_FILE_ACTIVITY",
		Status:         status,
		FailureReason:  reason,
		ClientIP:       clientIP,
		ClientPort:     clientPort,
		Username:       username,
		ClientVersion:  clientVer,
		ParticipantNum: participantNum,
		FileActivity: &FileActivity{
			Action: action,
			Path:   path,
			Target: target,
			Size:   size,
		},
		Mitre: MitreAttackInfo{
			Tactic:    tactic,
			Technique: technique,
			ID:        techniqueID,
		},
	}

	ctiLogger.LogEvent(event)
}
