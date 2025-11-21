package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/n0z0/cachedb/cdc"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	cacheDB        = "127.0.0.1:50051" // gRPC cache DB address
	privateKeyPath = "id_rsa"          // host key file
	host           = "0.0.0.0"
	port           = "2025"
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

	// PasswordCallback membaca dari Bolt **setiap kali login** (hot-reload user)
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			log.Printf("Login attempt for user: %s", c.User())

			// Get a value by key
			storedPassword, err := cdc.Get(c.User(), db)
			if err != nil {
				log.Printf("Authentication failed for user %s: user not found", c.User())
				return nil, fmt.Errorf("authentication failed")
			}
			if storedPassword == "" {
				log.Printf("Authentication failed for user %s: empty password", c.User())
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

	log.Printf("SFTP server listening on %s:%s (multi-user via Data %q)", host, port, cacheDB)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConn(conn, config)
	}
}

func handleConn(conn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	defer sshConn.Close()

	log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}

		go func() {
			for req := range requests {
				// payload[0..3] = uint32(len("sftp"))
				if req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
					req.Reply(true, nil)
					handleSFTP(channel)
				} else {
					req.Reply(false, nil)
				}
			}
		}()
	}
}

func handleSFTP(channel ssh.Channel) {
	server, err := sftp.NewServer(channel)
	if err != nil {
		log.Printf("Failed to create SFTP server: %v", err)
		return
	}
	defer server.Close()

	log.Println("SFTP session started")
	if err := server.Serve(); err == nil {
		log.Println("SFTP session closed")
	} else {
		log.Printf("SFTP server completed with error: %v", err)
	}
}

func generateHostKey(privateKeyPath string) (ssh.Signer, error) {
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		log.Printf("Generating new host key at %s", privateKeyPath)
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		f, err := os.Create(privateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create private key file: %w", err)
		}
		defer f.Close()
		if err := pem.Encode(f, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}); err != nil {
			return nil, fmt.Errorf("failed to encode private key: %w", err)
		}
		if err := f.Chmod(0600); err != nil {
			return nil, fmt.Errorf("failed to set permissions on key file: %w", err)
		}
	}
	priv, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return signer, nil
}
