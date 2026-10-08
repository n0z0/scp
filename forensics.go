package main

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/n0z0/cachedb/cdc"
	"github.com/n0z0/cachedb/proto/cachepb"
)

type ForensicsJob struct {
	FilePath       string // Absolute path pada disk lokal
	ReqPath        string // Path request SFTP
	ClientIP       string
	ClientPort     int
	Username       string
	ClientVer      string
	ParticipantNum int
	FileSize       int64
}

type ForensicsEngine struct {
	jobsChan chan *ForensicsJob
	workers  int
	db       cachepb.CacheClient
	quit     chan struct{}
	wg       sync.WaitGroup
}

var globalForensicsEngine *ForensicsEngine

func initForensicsEngine(workers int, db cachepb.CacheClient) *ForensicsEngine {
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
		if workers < 4 {
			workers = 4
		}
	}

	engine := &ForensicsEngine{
		jobsChan: make(chan *ForensicsJob, 1024), // Buffer 1024 jobs untuk load tinggi
		workers:  workers,
		db:       db,
		quit:     make(chan struct{}),
	}

	// Start bounded worker pool
	for i := 1; i <= workers; i++ {
		engine.wg.Add(1)
		go engine.worker(i)
	}

	globalForensicsEngine = engine
	log.Printf("[FORENSICS] Engine diinisialisasi dengan %d worker goroutines (Buffer: 1024)", workers)
	return engine
}

func (e *ForensicsEngine) Close() {
	if e == nil {
		return
	}
	close(e.quit)
	e.wg.Wait()
}

func enqueueForensicsJob(filePath, reqPath, clientIP string, clientPort int, username, clientVer string, participantNum int, size int64) {
	if globalForensicsEngine == nil {
		return
	}

	job := &ForensicsJob{
		FilePath:       filePath,
		ReqPath:        reqPath,
		ClientIP:       clientIP,
		ClientPort:     clientPort,
		Username:       username,
		ClientVer:      clientVer,
		ParticipantNum: participantNum,
		FileSize:       size,
	}

	// Non-blocking enqueue
	select {
	case globalForensicsEngine.jobsChan <- job:
	default:
		// Jika queue penuh, proses di goroutine terpisah agar koneksi SFTP tidak pernah block
		go globalForensicsEngine.processJob(job, 0)
	}
}

func (e *ForensicsEngine) worker(id int) {
	defer e.wg.Done()
	for {
		select {
		case job, ok := <-e.jobsChan:
			if !ok {
				return
			}
			e.processJob(job, id)
		case <-e.quit:
			return
		}
	}
}

func (e *ForensicsEngine) processJob(job *ForensicsJob, workerID int) {
	// Proteksi dari panic jika ada file malformed / corrupt exploit
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[FORENSICS][Worker %d] Panic recovery saat parsing %s: %v", workerID, job.ReqPath, r)
		}
	}()

	start := time.Now()

	// Pastikan file ada dan dapat dibaca
	f, err := os.Open(job.FilePath)
	if err != nil {
		log.Printf("[FORENSICS] Gagal membuka file %s untuk analisis: %v", job.FilePath, err)
		return
	}
	defer f.Close()

	// 1. Hitung Hashes (SHA-256 dan MD5)
	h256 := sha256.New()
	hMD5 := md5.New()
	multiWriter := io.MultiWriter(h256, hMD5)

	headerBuf := make([]byte, 512)
	n, _ := f.Read(headerBuf)
	_, _ = f.Seek(0, io.SeekStart)

	if _, err := io.Copy(multiWriter, f); err != nil {
		log.Printf("[FORENSICS] Gagal membaca seluruh stream file %s: %v", job.FilePath, err)
		return
	}

	meta := &FileForensicsData{
		SHA256:        hex.EncodeToString(h256.Sum(nil)),
		MD5:           hex.EncodeToString(hMD5.Sum(nil)),
		ExtraMetadata: make(map[string]string),
	}

	// Deteksi MIME Type
	meta.MimeType = http.DetectContentType(headerBuf[:n])

	ext := strings.ToLower(filepath.Ext(job.ReqPath))

	// 2. Cabang Parser Berdasarkan Ekstensi / Konten
	switch {
	case ext == ".docx" || ext == ".xlsx" || ext == ".pptx" || ext == ".odt" || ext == ".ods":
		parseOfficeXML(job.FilePath, meta)
	case ext == ".pdf" || bytes.HasPrefix(headerBuf[:n], []byte("%PDF")):
		parsePDF(job.FilePath, meta)
	case ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".webp" || strings.HasPrefix(meta.MimeType, "image/"):
		parseImage(job.FilePath, headerBuf[:n], meta)
	case ext == ".exe" || ext == ".dll" || bytes.HasPrefix(headerBuf[:n], []byte("MZ")):
		parsePEBinary(job.FilePath, meta)
	default:
		// File teks / generic scan
		if strings.HasPrefix(meta.MimeType, "text/") {
			meta.Software = "Plain Text / Script"
		}
	}

	meta.ParseDurationMs = float64(time.Since(start).Microseconds()) / 1000.0

	if meta.Author != "" || meta.Software != "" || meta.GPSCoordinates != "" || meta.PDBPath != "" {
		meta.ConfidenceScore = "HIGH"
	} else {
		meta.ConfidenceScore = "MEDIUM"
	}

	// 3. Catat ke CTI Logger
	if ctiLogger != nil {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "scp-honeypot"
		}

		event := &SCPCTIEvent{
			Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
			SensorID:       hostname,
			EventType:      "SFTP_FILE_FORENSICS",
			Status:         "analyzed",
			ClientIP:       job.ClientIP,
			ClientPort:     job.ClientPort,
			Username:       job.Username,
			ClientVersion:  job.ClientVer,
			ParticipantNum: job.ParticipantNum,
			FileActivity: &FileActivity{
				Action: "UPLOAD",
				Path:   job.ReqPath,
				Size:   job.FileSize,
			},
			FileForensics: meta,
			Mitre: MitreAttackInfo{
				Tactic:    "Command and Control",
				Technique: "Ingress Tool Transfer / File Attribution",
				ID:        "T1105",
			},
		}

		ctiLogger.LogEvent(event)
	}

	// 4. Korelasi ke CacheDB (Async)
	if e.db != nil {
		go func() {
			// Simpan berdasarkan hash file
			metaJSON, _ := json.Marshal(meta)
			_ = cdc.Set(fmt.Sprintf("meta:file:%s", meta.SHA256), string(metaJSON), e.db)

			// Simpan korelasi author ke IP penyerang
			if meta.Author != "" {
				_ = cdc.Set(fmt.Sprintf("meta:author:%s", job.ClientIP), meta.Author, e.db)
			}
			if meta.Software != "" {
				_ = cdc.Set(fmt.Sprintf("meta:software:%s", job.ClientIP), meta.Software, e.db)
			}
		}()
	}

	log.Printf("[FORENSICS] File %s selesai dianalisis dalam %.2fms | SHA256: %s... | Author: %q | Software: %q",
		job.ReqPath, meta.ParseDurationMs, meta.SHA256[:12], meta.Author, meta.Software)
}

// -------------------------------------------------------------------------------------
// Parser Office OpenXML (DOCX, XLSX, PPTX)
// -------------------------------------------------------------------------------------

type openXMLCoreProps struct {
	Title          string `xml:"title"`
	Subject        string `xml:"subject"`
	Creator        string `xml:"creator"`
	Description    string `xml:"description"`
	LastModifiedBy string `xml:"lastModifiedBy"`
	Revision       string `xml:"revision"`
	Created        string `xml:"created"`
	Modified       string `xml:"modified"`
}

type openXMLAppProps struct {
	Application string `xml:"Application"`
	AppVersion  string `xml:"AppVersion"`
	Company     string `xml:"Company"`
	Template    string `xml:"Template"`
	TotalTime   string `xml:"TotalTime"`
}

func parseOfficeXML(filePath string, meta *FileForensicsData) {
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return
	}
	defer r.Close()

	for _, f := range r.File {
		cleanName := strings.ToLower(f.Name)
		if cleanName == "docprops/core.xml" {
			rc, err := f.Open()
			if err == nil {
				var core openXMLCoreProps
				if xml.NewDecoder(rc).Decode(&core) == nil {
					meta.Author = strings.TrimSpace(core.Creator)
					meta.LastModifiedBy = strings.TrimSpace(core.LastModifiedBy)
					meta.Title = strings.TrimSpace(core.Title)
					meta.CreatedTime = strings.TrimSpace(core.Created)
					meta.ModifiedTime = strings.TrimSpace(core.Modified)
					if core.Revision != "" {
						meta.ExtraMetadata["revision"] = core.Revision
					}
				}
				rc.Close()
			}
		} else if cleanName == "docprops/app.xml" {
			rc, err := f.Open()
			if err == nil {
				var app openXMLAppProps
				if xml.NewDecoder(rc).Decode(&app) == nil {
					soft := strings.TrimSpace(app.Application)
					if app.AppVersion != "" {
						soft = fmt.Sprintf("%s (%s)", soft, app.AppVersion)
					}
					meta.Software = soft
					if app.Company != "" {
						meta.ExtraMetadata["company"] = app.Company
					}
					if app.Template != "" {
						meta.ExtraMetadata["template"] = app.Template
					}
				}
				rc.Close()
			}
		}
	}
}

// -------------------------------------------------------------------------------------
// Parser PDF Documents
// -------------------------------------------------------------------------------------

var (
	pdfAuthorReg   = regexp.MustCompile(`(?i)/Author\s*\(([^)]+)\)`)
	pdfCreatorReg  = regexp.MustCompile(`(?i)/Creator\s*\(([^)]+)\)`)
	pdfProducerReg = regexp.MustCompile(`(?i)/Producer\s*\(([^)]+)\)`)
	pdfTitleReg    = regexp.MustCompile(`(?i)/Title\s*\(([^)]+)\)`)
	pdfCreateDtReg = regexp.MustCompile(`(?i)/CreationDate\s*\(([^)]+)\)`)
	pdfModDtReg    = regexp.MustCompile(`(?i)/ModDate\s*\(([^)]+)\)`)
	pdfTZReg       = regexp.MustCompile(`[+-]\d{2}'\d{2}'?`)

	xmpCreatorReg  = regexp.MustCompile(`(?i)<dc:creator[^>]*>.*?<rdf:li[^>]*>([^<]+)</rdf:li>`)
	xmpProducerReg = regexp.MustCompile(`(?i)<pdf:Producer>([^<]+)</pdf:Producer>`)
	xmpToolReg     = regexp.MustCompile(`(?i)<xmp:CreatorTool>([^<]+)</xmp:CreatorTool>`)
)

func parsePDF(filePath string, meta *FileForensicsData) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}
	content := string(data)

	if m := pdfAuthorReg.FindStringSubmatch(content); len(m) > 1 {
		meta.Author = strings.TrimSpace(m[1])
	} else if m := xmpCreatorReg.FindStringSubmatch(content); len(m) > 1 {
		meta.Author = strings.TrimSpace(m[1])
	}

	var creator, producer string
	if m := pdfCreatorReg.FindStringSubmatch(content); len(m) > 1 {
		creator = strings.TrimSpace(m[1])
	} else if m := xmpToolReg.FindStringSubmatch(content); len(m) > 1 {
		creator = strings.TrimSpace(m[1])
	}

	if m := pdfProducerReg.FindStringSubmatch(content); len(m) > 1 {
		producer = strings.TrimSpace(m[1])
	} else if m := xmpProducerReg.FindStringSubmatch(content); len(m) > 1 {
		producer = strings.TrimSpace(m[1])
	}

	if creator != "" && producer != "" {
		meta.Software = fmt.Sprintf("%s / %s", creator, producer)
	} else if creator != "" {
		meta.Software = creator
	} else if producer != "" {
		meta.Software = producer
	}

	if m := pdfTitleReg.FindStringSubmatch(content); len(m) > 1 {
		meta.Title = strings.TrimSpace(m[1])
	}

	if m := pdfCreateDtReg.FindStringSubmatch(content); len(m) > 1 {
		meta.CreatedTime = strings.TrimSpace(m[1])
		if tz := pdfTZReg.FindString(m[1]); tz != "" {
			meta.DetectedTZ = "UTC" + strings.ReplaceAll(tz, "'", "")
		}
	}
	if m := pdfModDtReg.FindStringSubmatch(content); len(m) > 1 {
		meta.ModifiedTime = strings.TrimSpace(m[1])
	}
}

// -------------------------------------------------------------------------------------
// Parser Gambar (JPEG EXIF, PNG Chunks)
// -------------------------------------------------------------------------------------

func parseImage(filePath string, header []byte, meta *FileForensicsData) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	// 1. JPEG EXIF Parser
	if len(data) > 4 && data[0] == 0xFF && data[1] == 0xD8 {
		parseJPEGExif(data, meta)
		return
	}

	// 2. PNG Chunk Parser
	if bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		parsePNGChunks(data, meta)
		return
	}
}

func parseJPEGExif(data []byte, meta *FileForensicsData) {
	idx := 2
	for idx < len(data)-4 {
		if data[idx] != 0xFF {
			idx++
			continue
		}
		marker := data[idx+1]
		if marker == 0xDA || marker == 0xD9 { // SOS or EOI
			break
		}

		length := int(binary.BigEndian.Uint16(data[idx+2 : idx+4]))
		if idx+2+length > len(data) {
			break
		}

		// APP1 Marker (EXIF)
		if marker == 0xE1 && length > 8 {
			payload := data[idx+4 : idx+2+length]
			if bytes.HasPrefix(payload, []byte("Exif\x00\x00")) {
				parseTIFFHeader(payload[6:], meta)
				return
			}
		}

		idx += 2 + length
	}
}

func parseTIFFHeader(tiff []byte, meta *FileForensicsData) {
	if len(tiff) < 8 {
		return
	}
	var byteOrder binary.ByteOrder
	if tiff[0] == 'I' && tiff[1] == 'I' {
		byteOrder = binary.LittleEndian
	} else if tiff[0] == 'M' && tiff[1] == 'M' {
		byteOrder = binary.BigEndian
	} else {
		return
	}

	firstIFD := byteOrder.Uint32(tiff[4:8])
	if int(firstIFD) >= len(tiff) {
		return
	}

	readIFD(tiff, int(firstIFD), byteOrder, meta)
}

func readIFD(tiff []byte, offset int, order binary.ByteOrder, meta *FileForensicsData) {
	if offset+2 > len(tiff) {
		return
	}
	tagCount := int(order.Uint16(tiff[offset : offset+2]))
	curr := offset + 2

	var gpsOffset uint32

	for i := 0; i < tagCount; i++ {
		if curr+12 > len(tiff) {
			break
		}
		tag := order.Uint16(tiff[curr : curr+2])
		typ := order.Uint16(tiff[curr+2 : curr+4])
		count := order.Uint32(tiff[curr+4 : curr+8])
		valOffset := order.Uint32(tiff[curr+8 : curr+12])

		strVal := ""
		if typ == 2 && count > 0 { // ASCII String
			if count <= 4 {
				strVal = strings.TrimRight(string(tiff[curr+8:curr+8+int(count)]), "\x00")
			} else if int(valOffset+count) <= len(tiff) {
				strVal = strings.TrimRight(string(tiff[valOffset:valOffset+count]), "\x00")
			}
		}

		switch tag {
		case 0x010F: // Make
			meta.CameraMake = strVal
		case 0x0110: // Model
			meta.CameraModel = strVal
		case 0x0131: // Software
			meta.Software = strVal
		case 0x0132: // DateTime
			meta.CreatedTime = strVal
		case 0x013B: // Artist / Author
			meta.Author = strVal
		case 0x8825: // GPS Info IFD Pointer
			gpsOffset = valOffset
		}

		curr += 12
	}

	if meta.CameraMake != "" || meta.CameraModel != "" {
		if meta.ExtraMetadata == nil {
			meta.ExtraMetadata = make(map[string]string)
		}
		meta.ExtraMetadata["device"] = fmt.Sprintf("%s %s", meta.CameraMake, meta.CameraModel)
	}

	if gpsOffset > 0 && int(gpsOffset) < len(tiff) {
		meta.GPSCoordinates = parseGPSIFD(tiff, int(gpsOffset), order)
	}
}

func parseGPSIFD(tiff []byte, offset int, order binary.ByteOrder) string {
	if offset+2 > len(tiff) {
		return ""
	}
	tagCount := int(order.Uint16(tiff[offset : offset+2]))
	curr := offset + 2

	var latRef, lonRef string
	var lat, lon float64

	for i := 0; i < tagCount; i++ {
		if curr+12 > len(tiff) {
			break
		}
		tag := order.Uint16(tiff[curr : curr+2])
		valOffset := order.Uint32(tiff[curr+8 : curr+12])

		if tag == 1 { // GPSLatitudeRef
			latRef = strings.TrimRight(string(tiff[curr+8:curr+9]), "\x00")
		} else if tag == 3 { // GPSLongitudeRef
			lonRef = strings.TrimRight(string(tiff[curr+8:curr+9]), "\x00")
		} else if tag == 2 && int(valOffset+24) <= len(tiff) { // GPSLatitude Rational[3]
			lat = readRationalDegrees(tiff[valOffset:], order)
		} else if tag == 4 && int(valOffset+24) <= len(tiff) { // GPSLongitude Rational[3]
			lon = readRationalDegrees(tiff[valOffset:], order)
		}

		curr += 12
	}

	if lat != 0 && lon != 0 {
		if latRef == "S" {
			lat = -lat
		}
		if lonRef == "W" {
			lon = -lon
		}
		return fmt.Sprintf("%.6f, %.6f", lat, lon)
	}
	return ""
}

func readRationalDegrees(buf []byte, order binary.ByteOrder) float64 {
	dNum := order.Uint32(buf[0:4])
	dDen := order.Uint32(buf[4:8])
	mNum := order.Uint32(buf[8:12])
	mDen := order.Uint32(buf[12:16])
	sNum := order.Uint32(buf[16:20])
	sDen := order.Uint32(buf[20:24])

	deg := 0.0
	if dDen > 0 {
		deg += float64(dNum) / float64(dDen)
	}
	if mDen > 0 {
		deg += (float64(mNum) / float64(mDen)) / 60.0
	}
	if sDen > 0 {
		deg += (float64(sNum) / float64(sDen)) / 3600.0
	}
	return deg
}

func parsePNGChunks(data []byte, meta *FileForensicsData) {
	idx := 8 // Skip PNG magic
	for idx+8 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[idx : idx+4]))
		chunkType := string(data[idx+4 : idx+8])
		idx += 8

		if idx+length > len(data) {
			break
		}

		if chunkType == "tEXt" || chunkType == "zTXt" || chunkType == "iTXt" {
			chunkData := data[idx : idx+length]
			nullIdx := bytes.IndexByte(chunkData, 0)
			if nullIdx > 0 {
				key := strings.ToLower(string(chunkData[:nullIdx]))
				val := string(chunkData[nullIdx+1:])
				switch key {
				case "author", "artist":
					meta.Author = strings.TrimSpace(val)
				case "software":
					meta.Software = strings.TrimSpace(val)
				case "creation time":
					meta.CreatedTime = strings.TrimSpace(val)
				case "title":
					meta.Title = strings.TrimSpace(val)
				}
			}
		}

		idx += length + 4 // Skip data + CRC
	}
}

// -------------------------------------------------------------------------------------
// Parser Binary Executables (PE Windows PDB Paths)
// -------------------------------------------------------------------------------------

var pdbRegex = regexp.MustCompile(`(?i)[a-zA-Z]:\\[a-zA-Z0-9_\-\.\\]+\.pdb`)

func parsePEBinary(filePath string, meta *FileForensicsData) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	meta.Software = "Windows PE Executable / DLL"

	// Scan string PDB path
	if m := pdbRegex.Find(data); len(m) > 0 {
		meta.PDBPath = string(m)
		meta.ExtraMetadata["pdb_path"] = string(m)
	}
}
