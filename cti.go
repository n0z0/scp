package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/n0z0/cachedb/cdc"
	"github.com/n0z0/cachedb/proto/cachepb"
)

// ReconProfileInfo menyimpan korelasi metadata hasil pengintaian jaringan L4 (dari synwatcher via cachedb)
type ReconProfileInfo struct {
	SYNFingerprintHash string `json:"syn_hash,omitempty"`
	RiskScore          string `json:"risk_score,omitempty"`
	Severity           string `json:"severity,omitempty"`
	TargetService      string `json:"target_service,omitempty"`
	IntentCategory     string `json:"intent_category,omitempty"`
	ScanVelocity       string `json:"scan_velocity,omitempty"`
	EstimatedOS        string `json:"estimated_os,omitempty"`
	ScannerTool        string `json:"scanner_tool,omitempty"`
	ScanHits           string `json:"scan_hits,omitempty"`
	LastScan           string `json:"last_scan,omitempty"`
}

// SCPCTIEvent mencatat aktivitas interaksi otentikasi honeypot SFTP dan manipulasi file
type SCPCTIEvent struct {
	Timestamp      string             `json:"timestamp"` // ISO 8601 UTC
	SensorID       string             `json:"sensor_id"`
	SessionID      string             `json:"session_id,omitempty"`
	EventType      string             `json:"event_type"` // SFTP_LOGIN_SUCCESS, SFTP_AUTH_FAILED, SFTP_FILE_ACTIVITY
	Status         string             `json:"status"`     // success, failed
	FailureReason  string             `json:"failure_reason,omitempty"`
	ClientIP       string             `json:"client_ip"`
	ClientPort     int                `json:"client_port"`
	ReverseDNS     string             `json:"reverse_dns,omitempty"`
	Username       string             `json:"username"`
	Password       string             `json:"password,omitempty"`
	ClientVersion  string             `json:"client_version,omitempty"`
	ParticipantNum int                `json:"participant_number,omitempty"`
	ReconProfile   *ReconProfileInfo  `json:"recon_profile,omitempty"`
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

var rdnsCache sync.Map

func resolveReverseDNS(ipStr string) string {
	if val, ok := rdnsCache.Load(ipStr); ok {
		return val.(string)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	var r net.Resolver
	var host string
	names, err := r.LookupAddr(ctx, ipStr)
	if err == nil && len(names) > 0 {
		host = strings.TrimSuffix(names[0], ".")
	}
	rdnsCache.Store(ipStr, host)
	return host
}

func logCTIAuth(status, reason, clientIP string, clientPort int, username, password, clientVer string, participantNum int, db cachepb.CacheClient) {
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

	var recon *ReconProfileInfo
	var rDNS string
	if clientIP != "" && clientIP != "127.0.0.1" && clientIP != "::1" {
		rDNS = resolveReverseDNS(clientIP)
	}

	if db != nil {
		if rDNS != "" {
			_ = cdc.Set("actor:rdns:"+clientIP, rDNS, db)
		}
		if status == "success" {
			_ = cdc.Set("actor:intent:"+clientIP, "INITIAL_ACCESS_SFTP_SUCCESS", db)
			_ = cdc.Set("actor:risk:"+clientIP, "95", db)
			_ = cdc.Set("actor:severity:"+clientIP, "CRITICAL", db)
		}
		if dossier, found, err := cdc.GetActor(clientIP, db); err == nil && found && dossier != nil {
			recon = &ReconProfileInfo{
				SYNFingerprintHash: dossier.SynHash,
				RiskScore:          dossier.RiskScore,
				Severity:           dossier.Severity,
				TargetService:      dossier.TargetService,
				IntentCategory:     dossier.IntentCategory,
				ScanVelocity:       dossier.ScanVelocity,
				EstimatedOS:        dossier.EstimatedOs,
				ScannerTool:        dossier.ScannerTool,
				ScanHits:           dossier.ScanHits,
				LastScan:           dossier.LastActivity,
			}
			if status == "success" && recon.Severity != "" {
				log.Printf("[SOC] Terkorelasi Threat Actor %s (Risk: %s [%s], Tool: %s, SYN-Hash: %s) berhasil login SFTP", clientIP, recon.RiskScore, recon.Severity, recon.ScannerTool, recon.SYNFingerprintHash)
			}
		}
	}

	event := &SCPCTIEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		SensorID:       hostname,
		EventType:      eventType,
		Status:         status,
		FailureReason:  reason,
		ClientIP:       clientIP,
		ClientPort:     clientPort,
		ReverseDNS:     rDNS,
		Username:       username,
		Password:       password,
		ClientVersion:  clientVer,
		ParticipantNum: participantNum,
		ReconProfile:   recon,
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
