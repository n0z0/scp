package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/n0z0/cachedb/cdc"
	"github.com/pkg/sftp"
)

// CTIFileHandler mengimplementasikan sftp.Handlers (FileReader, FileWriter, FileCmder, FileLister)
// dengan pencatatan audit forensik CTI untuk setiap aktivitas file & direktori.
type CTIFileHandler struct {
	clientIP       string
	clientPort     int
	username       string
	clientVer      string
	participantNum int
	root           string
}

func newCTIFileHandler(sshConn *SessionMeta) sftp.Handlers {
	h := &CTIFileHandler{
		clientIP:       sshConn.ClientIP,
		clientPort:     sshConn.ClientPort,
		username:       sshConn.Username,
		clientVer:      sshConn.ClientVer,
		participantNum: sshConn.ParticipantNum,
		root:           ".",
	}

	return sftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	}
}

type SessionMeta struct {
	ClientIP       string
	ClientPort     int
	Username       string
	ClientVer      string
	ParticipantNum int
}

func parseSessionMeta(user string, ext map[string]string) *SessionMeta {
	meta := &SessionMeta{
		Username: user,
	}
	if ext != nil {
		meta.ClientIP = ext["client_ip"]
		meta.ClientPort, _ = strconv.Atoi(ext["client_port"])
		meta.ClientVer = ext["client_ver"]
		meta.ParticipantNum, _ = strconv.Atoi(ext["participant_number"])
	}
	return meta
}

func (h *CTIFileHandler) toRealPath(p string) string {
	clean := filepath.Clean(filepath.FromSlash(p))
	if clean == "." || clean == "/" || clean == "\\" {
		return h.root
	}
	if filepath.IsAbs(clean) {
		rel, err := filepath.Rel(string(filepath.Separator), clean)
		if err == nil {
			return filepath.Join(h.root, rel)
		}
	}
	return filepath.Join(h.root, clean)
}

// Fileread: Menangani pembacaan / download file (Method: Get)
func (h *CTIFileHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	realPath := h.toRealPath(r.Filepath)
	f, err := os.Open(realPath)
	if err != nil {
		logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "DOWNLOAD", r.Filepath, "", 0, "failed", err.Error())
		return nil, err
	}

	fi, statErr := f.Stat()
	var size int64
	if statErr == nil {
		size = fi.Size()
	}

	log.Printf("[SFTP] User %s membaca/mengunduh: %s (size: %d bytes)", h.username, r.Filepath, size)
	logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "DOWNLOAD", r.Filepath, "", size, "success", "")

	// Asinkron via Goroutine: daftarkan kepemilikan token file ke CacheDB untuk atribusi de-anonymization di lemes
	if globalCacheDB != nil {
		go func(fname, clientIP string) {
			baseName := filepath.Base(fname)
			_ = cdc.Set("token:owner:"+baseName, clientIP, globalCacheDB)
			_ = cdc.Set("token:download:"+baseName, clientIP, globalCacheDB)
			_ = cdc.Set("actor:last_download:"+clientIP, baseName, globalCacheDB)
		}(r.Filepath, h.clientIP)
	}

	return f, nil
}

// trackingWriter membungkus file writer untuk mencatat total byte yang ditulis saat upload
type trackingWriter struct {
	file    *os.File
	reqPath string
	handler *CTIFileHandler
	written int64
	mu      sync.Mutex
}

func (tw *trackingWriter) WriteAt(p []byte, off int64) (int, error) {
	n, err := tw.file.WriteAt(p, off)
	tw.mu.Lock()
	if off+int64(n) > tw.written {
		tw.written = off + int64(n)
	}
	tw.mu.Unlock()
	return n, err
}

func (tw *trackingWriter) Close() error {
	err := tw.file.Close()
	log.Printf("[SFTP] User %s selesai menulis/upload: %s (%d bytes)", tw.handler.username, tw.reqPath, tw.written)
	status := "success"
	reason := ""
	if err != nil {
		status = "failed"
		reason = err.Error()
	}
	logCTIFileActivity(tw.handler.clientIP, tw.handler.clientPort, tw.handler.username, tw.handler.clientVer, tw.handler.participantNum, "UPLOAD", tw.reqPath, "", tw.written, status, reason)

	// Non-blocking asynchronous metadata forensics extraction via Worker Pool
	if err == nil && tw.written > 0 {
		enqueueForensicsJob(tw.handler.toRealPath(tw.reqPath), tw.reqPath, tw.handler.clientIP, tw.handler.clientPort, tw.handler.username, tw.handler.clientVer, tw.handler.participantNum, tw.written)
	}

	return err
}

// Filewrite: Menangani penulisan / upload / edit file (Method: Put, Open)
func (h *CTIFileHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	realPath := h.toRealPath(r.Filepath)

	// Pastikan direktori induk ada
	if err := os.MkdirAll(filepath.Dir(realPath), 0755); err != nil {
		logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "UPLOAD", r.Filepath, "", 0, "failed", err.Error())
		return nil, err
	}

	f, err := os.OpenFile(realPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "UPLOAD", r.Filepath, "", 0, "failed", err.Error())
		return nil, err
	}

	log.Printf("[SFTP] User %s memulai upload/edit file: %s", h.username, r.Filepath)
	return &trackingWriter{
		file:    f,
		reqPath: r.Filepath,
		handler: h,
	}, nil
}

// Filecmd: Menangani perintah manajemen file/folder (Mkdir, Rmdir, Remove, Rename, dll)
func (h *CTIFileHandler) Filecmd(r *sftp.Request) error {
	realPath := h.toRealPath(r.Filepath)
	var err error

	switch r.Method {
	case "Mkdir":
		err = os.MkdirAll(realPath, 0755)
		status := "success"
		reason := ""
		if err != nil {
			status = "failed"
			reason = err.Error()
		}
		log.Printf("[SFTP] User %s membuat direktori: %s", h.username, r.Filepath)
		logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "MKDIR", r.Filepath, "", 0, status, reason)

	case "Rmdir":
		err = os.Remove(realPath)
		status := "success"
		reason := ""
		if err != nil {
			status = "failed"
			reason = err.Error()
		}
		log.Printf("[SFTP] User %s menghapus direktori: %s", h.username, r.Filepath)
		logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "RMDIR", r.Filepath, "", 0, status, reason)

	case "Remove":
		err = os.Remove(realPath)
		status := "success"
		reason := ""
		if err != nil {
			status = "failed"
			reason = err.Error()
		}
		log.Printf("[SFTP] User %s menghapus file: %s", h.username, r.Filepath)
		logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "DELETE", r.Filepath, "", 0, status, reason)

	case "Rename":
		realTarget := h.toRealPath(r.Target)
		err = os.Rename(realPath, realTarget)
		status := "success"
		reason := ""
		if err != nil {
			status = "failed"
			reason = err.Error()
		}
		log.Printf("[SFTP] User %s mengubah nama file: %s -> %s", h.username, r.Filepath, r.Target)
		logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "RENAME", r.Filepath, r.Target, 0, status, reason)

	default:
		return fmt.Errorf("method %s not supported", r.Method)
	}

	return err
}

// listerAt implementasi sftp.ListerAt
type listerAt []os.FileInfo

func (l listerAt) ListAt(f []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(f, l[offset:])
	if offset+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

// Filelist: Menangani melihat direktori dan info berkas (Method: List, Stat)
func (h *CTIFileHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	realPath := h.toRealPath(r.Filepath)

	switch r.Method {
	case "List":
		entries, err := os.ReadDir(realPath)
		if err != nil {
			logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "LIST_DIR", r.Filepath, "", 0, "failed", err.Error())
			return nil, err
		}
		var list []os.FileInfo
		for _, entry := range entries {
			info, err := entry.Info()
			if err == nil {
				list = append(list, info)
			}
		}
		log.Printf("[SFTP] User %s melihat isi direktori: %s (%d item)", h.username, r.Filepath, len(list))
		logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "LIST_DIR", r.Filepath, "", int64(len(list)), "success", "")
		return listerAt(list), nil

	case "Stat":
		fi, err := os.Stat(realPath)
		if err != nil {
			logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "STAT", r.Filepath, "", 0, "failed", err.Error())
			return nil, err
		}
		logCTIFileActivity(h.clientIP, h.clientPort, h.username, h.clientVer, h.participantNum, "STAT", r.Filepath, "", fi.Size(), "success", "")
		return listerAt([]os.FileInfo{fi}), nil

	default:
		return nil, fmt.Errorf("method %s not supported", r.Method)
	}
}
