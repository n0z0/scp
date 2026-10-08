package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/n0z0/cachedb/cdc"
	"golang.org/x/crypto/ssh"
)

var version = "dev"
var showVersion = flag.Bool("version", false, "Tampilkan versi lalu keluar")

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Println("scp", version)
		return
	}
	log.Printf("[*] scp %s starting...", version)
	// Connect to cache DB server
	db, conn, err := cdc.Connect(cacheDB)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Siapkan host key
	privateKey, err := generateHostKey(privateKeyPath)
	if err != nil {
		log.Fatalf("Error loading private key: %v", err)
	}

	// Inisialisasi CTI Logger untuk merekam otentikasi honeypot
	cti, err := initCTILogger(CTI_LOG)
	if err != nil {
		log.Printf("[WARN] Gagal membuka log CTI: %v", err)
	} else {
		defer cti.Close()
		log.Printf("[*] CTI Logging aktif -> %s", CTI_LOG)
	}

	// PasswordCallback membaca dari Cache DB **setiap kali login** (hot-reload user)
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			log.Printf("Login attempt for user: %s", c.User())

			remoteHost, remotePortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
			remotePort, _ := strconv.Atoi(remotePortStr)
			clientVer := string(c.ClientVersion())

			// Get a value by key
			storedPassword, err := cdc.Get(c.User(), db)
			if err != nil {
				log.Printf("Authentication failed for user %s: user not found", c.User())
				go logCTIAuth("failed", "user_not_found_in_cache", remoteHost, remotePort, c.User(), string(pass), clientVer, 0)
				return nil, fmt.Errorf("authentication failed")
			}
			// cek password kosong
			if storedPassword == "" {
				log.Printf("Authentication failed for user %s: empty password", c.User())
				go logCTIAuth("failed", "empty_password_in_cache", remoteHost, remotePort, c.User(), string(pass), clientVer, 0)
				return nil, fmt.Errorf("authentication failed")
			}
			// cek jika username tidak sama dengan ip
			if c.User() != remoteHost {
				log.Printf("Authentication failed for user %s: username does not match IP %s", c.User(), remoteHost)
				go logCTIAuth("failed", "username_ip_mismatch", remoteHost, remotePort, c.User(), string(pass), clientVer, 0)
				return nil, fmt.Errorf("authentication failed")
			}

			log.Printf("Retrieved password for user %s", c.User())

			// verifikasi plain text
			if string(pass) == storedPassword {
				log.Printf("Authentication successful for user: %s", c.User())
				log.Printf("Password: %s", string(pass))
				port, err := strconv.Atoi(string(pass))
				if err != nil {
					port = 0
				}
				peserta := port % MOD
				log.Printf("Assigned participant number: %d", peserta)
				// append to log file & CTI log
				go logPesertaMasuk(fmt.Sprintf("Siswa %d", peserta), c.User(), string(pass))
				go logCTIAuth("success", "", remoteHost, remotePort, c.User(), string(pass), clientVer, peserta)
				go PlayNotificationSound(peserta)
				go NotifikasiDesktop("Berhasil Login", c.User()+" : Siswa "+strconv.Itoa(peserta))

				return nil, nil
			}

			log.Printf("%s Authentication failed for user %s: invalid password %s", storedPassword, c.User(), string(pass))
			go logCTIAuth("failed", "invalid_password", remoteHost, remotePort, c.User(), string(pass), clientVer, 0)
			return nil, fmt.Errorf("authentication failed")
		},
	}
	config.AddHostKey(privateKey)

	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		log.Fatalf("Failed to listen on %s:%s: %v", host, port, err)
	}
	defer ln.Close()

	log.Printf("SFTP server listening on %s:%s (multi-user via CacheDB %q)", host, port, cacheDB)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConn(conn, config)
	}
}
