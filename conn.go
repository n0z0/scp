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

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

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
