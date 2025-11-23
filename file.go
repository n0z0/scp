package main

import (
	"fmt"
	"log"
	"os"
	"time"
)

func logPesertaMasuk(peserta, user, pass string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	logEntry := fmt.Sprintf("[%s] Peserta: %s | %s:%s",
		timestamp, peserta, user, pass)

	log.Println(logEntry)

	// Also log to file
	f, err := os.OpenFile(MASUK_LOG, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening log file: %v", err)
		return
	}
	defer f.Close()

	_, err = f.WriteString(logEntry + "\n")
	if err != nil {
		log.Printf("Error writing to log file: %v", err)
	}
}
