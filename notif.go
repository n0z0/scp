package main

import (
	"bytes"
	_ "embed"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/faiface/beep"
	"github.com/faiface/beep/speaker"
	"github.com/faiface/beep/wav"
	"github.com/gen2brain/beeep"
)

//go:embed art/srye.wav
var notifSrye []byte

//go:embed art/ddmushi.wav
var notifDDm []byte

//go:embed art/tot2wuk2.wav
var notifTwk []byte

//go:embed art/indo.png
var indoPng []byte

var (
	iconPath string
	iconOnce sync.Once
)

// initIcon akan memastikan file PNG ada di disk (temp dir) tepat sekali
func initIcon() (string, error) {
	var err error
	iconOnce.Do(func() {
		tmpDir := os.TempDir()
		iconPath = filepath.Join(tmpDir, "indo.png")

		// cek sudah ada atau belum
		if _, statErr := os.Stat(iconPath); os.IsNotExist(statErr) {
			// belum ada → tulis
			err = os.WriteFile(iconPath, indoPng, 0o644)
		}
	})
	return iconPath, err
}

func NotifikasiDesktop(judul, pesan string) error {
	path, err := initIcon()
	if err != nil {
		return err
	}

	return beeep.Notify(judul, pesan, path)
}

func PlayNotificationSound(nomor int) {
	// pilih audio yang akan diputar
	index := nomor % 3
	var notifWav []byte
	switch index {
	case 0:
		notifWav = notifSrye
	case 1:
		notifWav = notifDDm
	case 2:
		notifWav = notifTwk
	default:
		// Kembalikan error jika indeks tidak valid
		notifWav = notifTwk
	}
	// decode WAV dari byte yang di-embed
	streamer, format, err := wav.Decode(bytes.NewReader(notifWav))
	if err != nil {
		log.Fatal("gagal decode wav:", err)
	}
	defer streamer.Close()

	// init speaker sesuai format audio
	err = speaker.Init(format.SampleRate, format.SampleRate.N(time.Second/10))
	if err != nil {
		log.Fatal("gagal init speaker:", err)
	}

	done := make(chan struct{})

	// play sampai selesai
	speaker.Play(beep.Seq(streamer, beep.Callback(func() {
		close(done)
	})))

	<-done
}
