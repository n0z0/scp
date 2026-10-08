# scp

**SFTP Honeypot Server** yang terintegrasi dengan [synwatcher](https://github.com/n0z0/synwatcher) dan [cacheDB](https://github.com/n0z0/cachedb).

Server ini mendengarkan pada port **`60606`** dan mengimplementasikan mekanisme otentikasi dinamis (*port knocking honeypot*):
- **Username:** Alamat IP penyerang/klien yang melakukan koneksi.
- **Password:** Nomor port **terakhir** yang di-scan oleh IP tersebut (yang ditangkap oleh `synwatcher` dan tersimpan di `cacheDB`).

```mermaid
flowchart LR
    A[Penyerang] -- "1. Scan Port X" --> B[synwatcher]
    B -- "2. Set(IP, Port X)" --> C[(cacheDB :50051)]
    A -- "3. SFTP Connect :60606<br>user=IP, pass=X" --> D[scp Server]
    D -- "4. Get(IP) == pass?" --> C
    D -- "5. Valid!" --> E[Audio & Notif Desktop<br>Log CTI & Peserta]
```

---

## Mekanisme Honeypot

1. Penyerang men-scan port target menggunakan scanner (seperti `nmap` atau script khusus).
2. `synwatcher` mendeteksi paket SYN/UDP dan mendaftarkan pasangan `IP -> Port` ke `cacheDB`.
3. Penyerang mencoba terhubung ke SFTP Server (`scp`) pada port **`60606`**:
   - Jika username cocok dengan IP klien DAN password cocok dengan port yang tersimpan di `cacheDB`:
     - Otentikasi **berhasil**.
     - Nomor urut peserta dihitung: `Port mod 30 = Nomor Urut`.
     - Memutar audio notifikasi dan memunculkan pop-up desktop.
     - Dicatat ke riwayat peserta masuk (`peserta_masuk.log`).
     - Dicatat ke log terstruktur CTI (`scp_cti.jsonl`).
   - Jika kredensial salah atau IP belum pernah men-scan:
     - Otentikasi ditolak dan dicatat ke log CTI sebagai percobaan akses gagal.

---

## Cyber Threat Intelligence (CTI) Logging

Setiap interaksi login (berhasil maupun gagal) otomatis dicatat ke file **`scp_cti.jsonl`** dalam format JSON Lines yang siap di-ingest ke SIEM, Elastic, Wazuh, atau MISP/OpenCTI.

Log ini memetakan event ke taktik dan teknik **MITRE ATT&CK**:
- **Login Berhasil:** `Valid Accounts` (`T1078`), Tactic: `Initial Access`.
- **Login Gagal:** `Brute Force: Password Guessing` (`T1110.001`), Tactic: `Credential Access` / `Initial Access`.

### Contoh Format Log CTI (`scp_cti.jsonl`)

**Percobaan Login Berhasil:**
```json
{
  "timestamp": "2026-10-08T02:08:15.123456789Z",
  "sensor_id": "honeypot-node-1",
  "event_type": "SFTP_LOGIN_SUCCESS",
  "status": "success",
  "client_ip": "192.168.1.150",
  "client_port": 54321,
  "username": "192.168.1.150",
  "password": "80",
  "client_version": "SSH-2.0-OpenSSH_9.6",
  "participant_number": 20,
  "mitre_attack": {
    "tactic": "Initial Access",
    "technique": "Valid Accounts: Default/Known Accounts",
    "technique_id": "T1078"
  }
}
```

**Percobaan Login Gagal:**
```json
{
  "timestamp": "2026-10-08T02:08:20.987654321Z",
  "sensor_id": "honeypot-node-1",
  "event_type": "SFTP_AUTH_FAILED",
  "status": "failed",
  "failure_reason": "invalid_password",
  "client_ip": "192.168.1.150",
  "client_port": 54322,
  "username": "192.168.1.150",
  "password": "wrongpassword",
  "client_version": "SSH-2.0-libssh_0.10.4",
  "mitre_attack": {
    "tactic": "Initial Access",
    "technique": "Brute Force: Password Guessing",
    "technique_id": "T1110.001"
  }
}
```

---

## Instalasi & Upgrade Otomatis

### Windows (PowerShell)
Jalankan perintah berikut untuk mengunduh binary rilis terbaru dan otomatis mendaftarkannya ke PATH pengguna:
```powershell
irm https://raw.githubusercontent.com/n0z0/scp/main/install.ps1 | iex
```
*(Bisa dijalankan kapan saja untuk upgrade ke versi terbaru).*

### Linux (Bash)
Jalankan perintah berikut di terminal:
```bash
curl -fsSL https://raw.githubusercontent.com/n0z0/scp/main/install.sh | bash
```
*(Binary otomatis dipasang sebagai `scp-server` ke `/usr/local/bin` atau `~/.local/bin` agar tidak bentrok dengan utilitas openSSH `scp` bawaan Linux).*

---

## Menjalankan Server

### Kebutuhan
1. **[cacheDB](https://github.com/n0z0/cachedb)** aktif di `127.0.0.1:50051`.
2. **[synwatcher](https://github.com/n0z0/synwatcher)** aktif memantau interface jaringan target.

### Menjalankan Langsung
```powershell
# Windows
scp

# Linux
scp-server
```

Server akan otomatis:
- Menghasilkan host key `id_rsa` jika belum ada.
- Membuka port listening SFTP di `0.0.0.0:60606`.
- Mengaktifkan logging CTI ke `scp_cti.jsonl`.

### Menguji Koneksi (Klien)
```powershell
# Contoh dari IP 192.168.1.150 setelah men-scan port 80 pada mesin honeypot:
sftp -P 60606 192.168.1.150@<IP_HONEYPOT>
# Masukkan password: 80
```

---

## Release

Release dibuat otomatis oleh [GitHub Actions](.github/workflows/release.yml) setiap kali ada push ke branch `main`:
- Versi patch dinaikkan secara otomatis dari tag terakhir (misal `v0.1.1` -> `v0.1.2`).
- Binary langsung siap pakai (`scp_windows_amd64.exe` dan `scp_linux_amd64`) serta arsip bundel di-upload langsung ke halaman Releases.

---

## Lisensi
[GNU AGPL v3](LICENSE)
