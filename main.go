package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/n0z0/cachedb/cdc"
	"golang.org/x/crypto/ssh"
)

func main() {
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

	// PasswordCallback membaca dari Cache DB **setiap kali login** (hot-reload user)
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			log.Printf("Login attempt for user: %s", c.User())

			// Get a value by key
			storedPassword, err := cdc.Get(c.User(), db)
			if err != nil {
				log.Printf("Authentication failed for user %s: user not found", c.User())
				return nil, fmt.Errorf("authentication failed")
			}
			// cek password kosong
			if storedPassword == "" {
				log.Printf("Authentication failed for user %s: empty password", c.User())
				return nil, fmt.Errorf("authentication failed")
			}
			// cek jika username tidak sama dengan ip
			if c.User() != strings.Split(c.RemoteAddr().String(), ":")[0] {
				log.Printf("Authentication failed for user %s: username does not match IP %s", c.User(), strings.Split(c.RemoteAddr().String(), ":")[0])
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
				peserta := port % 30
				log.Printf("Assigned participant number: %d", peserta)
				// append to log file
				logPesertaMasuk(fmt.Sprintf("Siswa %d", peserta), c.User(), string(pass))

				return nil, nil
			}

			log.Printf("%s Authentication failed for user %s: invalid password %s", storedPassword, c.User(), string(pass))
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
