#!/usr/bin/env bash
#
# scp Server Installer / Upgrader for Linux
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/n0z0/scp/main/install.sh | bash
#   atau
#   ./install.sh [version]
#
set -euo pipefail

REPO="n0z0/scp"
VERSION="${1:-latest}"
INSTALL_DIR="/usr/local/bin"

USE_SUDO=false
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    USE_SUDO=true
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

echo "=========================================="
echo " scp Server Installer / Upgrader (Linux)  "
echo "=========================================="

ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64) TARGET_ARCH="amd64" ;;
  aarch64|arm64) TARGET_ARCH="arm64" ;;
  *)
    echo "[!] Arsitektur ${ARCH} tidak didukung secara otomatis."
    exit 1
    ;;
esac

if [ "${VERSION}" = "latest" ]; then
  echo "[*] Memeriksa rilis terbaru dari GitHub..."
  TARGET_TAG=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  if [ -z "${TARGET_TAG}" ]; then
    echo "[!] Gagal mendapatkan tag rilis terbaru dari GitHub."
    exit 1
  fi
else
  case "${VERSION}" in
    v*) TARGET_TAG="${VERSION}" ;;
    *)  TARGET_TAG="v${VERSION}" ;;
  esac
fi

echo "[*] Target versi: ${TARGET_TAG} (linux/${TARGET_ARCH})"

# Cek versi terpasang
EXISTING_BIN="$(command -v scp-server 2>/dev/null || command -v scp-honeypot 2>/dev/null || true)"
if [ -n "${EXISTING_BIN}" ]; then
  CURRENT_VER="$(${EXISTING_BIN} -version 2>/dev/null || echo "unknown")"
  echo "[*] Versi terpasang saat ini: ${CURRENT_VER}"
  if [[ "${CURRENT_VER}" == *"${TARGET_TAG}"* ]]; then
    echo "[OK] scp sudah pada versi terbaru (${TARGET_TAG})."
    exit 0
  fi
fi

# Unduh Binary Langsung
# Di Linux, nama binary diberi nama scp-server agar tidak menimpa utilitas standar openSSH 'scp'
BIN_NAME="scp_linux_${TARGET_ARCH}"
DIRECT_URL="https://github.com/${REPO}/releases/download/${TARGET_TAG}/${BIN_NAME}"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

EXTRACTED_BIN="${TEMP_DIR}/scp-server"

echo "[*] Mengunduh binary langsung dari ${DIRECT_URL}..."
if curl -fsSL "${DIRECT_URL}" -o "${EXTRACTED_BIN}"; then
  echo "[*] Binary langsung berhasil diunduh."
else
  echo "[*] Binary langsung tidak ditemukan, mencoba tar.gz bundel..."
  TAR_NAME="scp_${TARGET_TAG}_linux_${TARGET_ARCH}.tar.gz"
  TAR_URL="https://github.com/${REPO}/releases/download/${TARGET_TAG}/${TAR_NAME}"
  if curl -fsSL "${TAR_URL}" -o "${TEMP_DIR}/${TAR_NAME}"; then
    tar -xzf "${TEMP_DIR}/${TAR_NAME}" -C "${TEMP_DIR}"
    FOUND_BIN=$(find "${TEMP_DIR}" -type f -name "scp" -o -name "scp-server" | head -n1)
    if [ -n "${FOUND_BIN}" ]; then
      EXTRACTED_BIN="${FOUND_BIN}"
    fi
  else
    echo "[!] Gagal mengunduh binary rilis Linux."
    exit 1
  fi
fi

echo "[*] Memasang ke ${INSTALL_DIR}/scp-server..."
if [ "${USE_SUDO}" = true ]; then
  sudo mkdir -p "${INSTALL_DIR}"
  sudo cp -f "${EXTRACTED_BIN}" "${INSTALL_DIR}/scp-server"
  sudo chmod +x "${INSTALL_DIR}/scp-server"
else
  mkdir -p "${INSTALL_DIR}"
  cp -f "${EXTRACTED_BIN}" "${INSTALL_DIR}/scp-server"
  chmod +x "${INSTALL_DIR}/scp-server"

  if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
    echo "[*] Menambahkan ${INSTALL_DIR} ke PATH..."
    PROFILE_FILE=""
    if [ -f "${HOME}/.bashrc" ]; then
      PROFILE_FILE="${HOME}/.bashrc"
    elif [ -f "${HOME}/.zshrc" ]; then
      PROFILE_FILE="${HOME}/.zshrc"
    elif [ -f "${HOME}/.profile" ]; then
      PROFILE_FILE="${HOME}/.profile"
    fi

    if [ -n "${PROFILE_FILE}" ]; then
      echo "export PATH=\"\$PATH:${INSTALL_DIR}\"" >> "${PROFILE_FILE}"
      echo "[*] Ditambahkan ke ${PROFILE_FILE}."
    fi
  fi
fi

echo "=========================================="
echo " Sukses! scp-server terpasang/diupgrade.  "
echo " Versi: ${TARGET_TAG}                     "
echo "=========================================="
echo "Jalankan perintah langsung: scp-server -help"
