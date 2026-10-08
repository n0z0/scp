[CmdletBinding()]
param (
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\scp"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " scp Server Installer / Upgrader (Windows)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Tentukan tag rilis
$Repo = "n0z0/scp"
if ($Version -eq "latest") {
    Write-Host "[*] Memeriksa rilis terbaru dari GitHub..." -ForegroundColor Yellow
    try {
        $ReleaseUrl = "https://api.github.com/repos/$Repo/releases/latest"
        $Release = Invoke-RestMethod -Uri $ReleaseUrl -Headers @{ "User-Agent" = "PowerShell" }
        $TargetTag = $Release.tag_name
    } catch {
        Write-Error "Gagal mendapatkan metadata rilis terbaru: $_"
    }
} else {
    if (-not $Version.StartsWith("v")) {
        $TargetTag = "v" + $Version
    } else {
        $TargetTag = $Version
    }
}

Write-Host "[*] Target versi: $TargetTag" -ForegroundColor Green

# 2. Cek apakah versi sudah terpasang
$CurrentExe = Join-Path $InstallDir "scp.exe"
if (Test-Path $CurrentExe) {
    try {
        $InstalledVer = (& $CurrentExe -version 2>&1).Trim()
        Write-Host "[*] Versi terpasang saat ini: $InstalledVer" -ForegroundColor Cyan
        if ($InstalledVer -like "*$TargetTag*") {
            Write-Host "[OK] scp sudah berada pada versi terbaru ($TargetTag)." -ForegroundColor Green
            Write-Host "    Lokasi: $CurrentExe"
            $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
            if ($UserPath -notlike "*$InstallDir*") {
                $UpdatedPath = $UserPath.TrimEnd(';') + ';' + $InstallDir
                [Environment]::SetEnvironmentVariable("Path", $UpdatedPath, "User")
                $env:Path = "$env:Path;$InstallDir"
                Write-Host "[OK] PATH berhasil ditambahkan." -ForegroundColor Green
            }
            return
        }
    } catch {}
}

# 3. Download dan pasang binary langsung
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$DirectExeUrl = "https://github.com/$Repo/releases/download/$TargetTag/scp_windows_amd64.exe"
$TargetExePath = Join-Path $InstallDir "scp.exe"
$TempExePath = Join-Path $InstallDir ("scp_new_" + [Guid]::NewGuid().ToString('N') + ".exe")

Write-Host "[*] Mengunduh binary langsung dari $DirectExeUrl ..." -ForegroundColor Yellow
$Downloaded = $false
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $DirectExeUrl -OutFile $TempExePath -UseBasicParsing
    Move-Item -Path $TempExePath -Destination $TargetExePath -Force
    $Downloaded = $true
} catch {
    # Fallback ke format zip jika binary telanjang belum ada
    Write-Host "[*] Binary langsung tidak ditemukan, mencoba unduh dari zip bundel..." -ForegroundColor Gray
    Remove-Item -Path $TempExePath -Force -ErrorAction SilentlyContinue

    $ZipName = "scp_" + $TargetTag + "_windows_amd64.zip"
    $ZipUrl = "https://github.com/$Repo/releases/download/$TargetTag/$ZipName"
    $TempZip = Join-Path $env:TEMP $ZipName
    $TempExtract = Join-Path $env:TEMP ("scp_ext_" + [Guid]::NewGuid().ToString('N'))

    Invoke-WebRequest -Uri $ZipUrl -OutFile $TempZip -UseBasicParsing
    Expand-Archive -Path $TempZip -DestinationPath $TempExtract -Force
    $ExtractedExe = Get-ChildItem -Path $TempExtract -Filter "scp.exe" -Recurse | Select-Object -First 1
    if ($ExtractedExe) {
        Copy-Item -Path $ExtractedExe.FullName -Destination $TargetExePath -Force
        $Downloaded = $true
    }
    Remove-Item -Path $TempZip -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TempExtract -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $Downloaded) {
    Write-Error "Gagal memasang binary scp."
}

# 4. Daftarkan ke PATH User
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "[*] Menambahkan $InstallDir ke PATH pengguna..." -ForegroundColor Yellow
    $UpdatedPath = $UserPath.TrimEnd(';') + ';' + $InstallDir
    [Environment]::SetEnvironmentVariable("Path", $UpdatedPath, "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "[OK] Direktori berhasil ditambahkan ke PATH!" -ForegroundColor Green
} else {
    Write-Host "[*] Direktori sudah ada di PATH." -ForegroundColor Gray
}

# 5. Selesai
Write-Host "==========================================" -ForegroundColor Green
Write-Host " Sukses! scp Server berhasil dipasang/diupgrade." -ForegroundColor Green
Write-Host " Versi: $TargetTag" -ForegroundColor Green
Write-Host " Lokasi: $CurrentExe" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Catatan:"
Write-Host "1. Pastikan cacheDB aktif di 127.0.0.1:50051."
Write-Host "2. Buka terminal baru dan jalankan langsung:"
Write-Host '   scp' -ForegroundColor Yellow
