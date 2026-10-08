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
	FileActivity   *FileActivity      `json:"file_activity,omitempty"`
	FileForensics  *FileForensicsData `json:"file_forensics,omitempty"`
	Mitre          MitreAttackInfo    `json:"mitre_attack"`
}

type FileActivity struct {
	Action string `json:"action"` // UPLOAD, DOWNLOAD, LIST_DIR, STAT, DELETE, RENAME, MKDIR, RMDIR
	Path   string `json:"path"`
	Target string `json:"target_path,omitempty"` // untuk rename/symlink
	Size   int64  `json:"size_bytes,omitempty"`
}

// FileForensicsData menyimpan metadata forensik mendalam dari file yang di-upload
type FileForensicsData struct {
	SHA256          string            `json:"sha256,omitempty"`
	MD5             string            `json:"md5,omitempty"`
	MimeType        string            `json:"mime_type,omitempty"`
	Author          string            `json:"author,omitempty"`
	LastModifiedBy  string            `json:"last_modified_by,omitempty"`
	CreatedTime     string            `json:"created_time,omitempty"`
	ModifiedTime    string            `json:"modified_time,omitempty"`
	Software        string            `json:"software,omitempty"`
	Title           string            `json:"title,omitempty"`
	DetectedTZ      string            `json:"detected_timezone,omitempty"`
	CameraMake      string            `json:"camera_make,omitempty"`
	CameraModel     string            `json:"camera_model,omitempty"`
	GPSCoordinates  string            `json:"gps_coordinates,omitempty"`
	PDBPath         string            `json:"pdb_path,omitempty"`
	ExtraMetadata   map[string]string `json:"extra_metadata,omitempty"`
	ParseDurationMs float64           `json:"parse_duration_ms,omitempty"`
	ConfidenceScore string            `json:"confidence_score,omitempty"`
}

type MitreAttackInfo struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	ID        string `json:"technique_id"`
}

type CTILogger struct {
	file      *os.File
	eventChan chan *SCPCTIEvent
	quit      chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
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

	logger := &CTILogger{
		file:      f,
		eventChan: make(chan *SCPCTIEvent, 2048), // Buffer tinggi untuk konkurensi ekstrem
		quit:      make(chan struct{}),
	}

	// Worker goroutine untuk penulisan asinkron tanpa blocking I/O di main thread
	logger.wg.Add(1)
	go func() {
		defer logger.wg.Done()
		for {
			select {
			case event, ok := <-logger.eventChan:
				if !ok {
					return
				}
				data, err := json.Marshal(event)
				if err != nil {
					log.Printf("[CTI] Gagal serialize JSON event: %v", err)
					continue
				}
				logger.mu.Lock()
				logger.file.Write(append(data, '\n'))
				logger.mu.Unlock()
			case <-logger.quit:
				// Drain sisa event sebelum exit
				for {
					select {
					case event := <-logger.eventChan:
						data, err := json.Marshal(event)
						if err == nil {
							logger.mu.Lock()
							logger.file.Write(append(data, '\n'))
							logger.mu.Unlock()
						}
					default:
						return
					}
				}
			}
		}
	}()

	ctiLogger = logger
	return ctiLogger, nil
}

func (l *CTILogger) Close() {
	if l != nil {
		close(l.quit)
		l.wg.Wait()
		if l.file != nil {
			l.file.Close()
		}
	}
}

func (l *CTILogger) LogEvent(event *SCPCTIEvent) {
	if l == nil {
		return
	}
	// Non-blocking channel send untuk zero latency ke koneksi client
	select {
	case l.eventChan <- event:
	default:
		// Jika buffer penuh (beban luar biasa), jalankan fallback sync di goroutine terpisah
		go func() {
			data, err := json.Marshal(event)
			if err == nil && l.file != nil {
				l.mu.Lock()
				defer l.mu.Unlock()
				l.file.Write(append(data, '\n'))
			}
		}()
	}
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
