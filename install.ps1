# Bug Hunter - Windows Installer (PowerShell)
# Run in PowerShell:  Set-ExecutionPolicy -Scope Process Bypass; .\install.ps1
# Safe to re-run.

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[*] Bug Hunter Windows installer" -ForegroundColor Cyan

# Python
Write-Host "[*] Checking Python..."
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $py) {
    Write-Host "[-] Python not found. Install Python 3.9+ from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "    Make sure to check 'tcl/tk and IDLE' and 'Add python.exe to PATH' during install." -ForegroundColor Yellow
    exit 1
}
Write-Host "    Found: $($py.Source)" -ForegroundColor Green

# tkinter check
try {
    & $py.Source -c "import tkinter" 2>$null
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Host "    tkinter OK" -ForegroundColor Green
} catch {
    Write-Host "[!] tkinter is missing. Re-run the Python installer and select 'tcl/tk and IDLE'." -ForegroundColor Yellow
}

# Pillow
Write-Host "[*] Installing Python dependencies (Pillow)..."
& $py.Source -m pip install -r (Join-Path $ScriptDir "requirements.txt")
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] pip install failed. Try running as Administrator or use a virtualenv." -ForegroundColor Yellow
}

# Go tools
Write-Host "[*] Checking Go..."
$go = Get-Command go -ErrorAction SilentlyContinue
if (-not $go) {
    Write-Host "[-] Go not found. Install from https://go.dev/dl/" -ForegroundColor Yellow
    Write-Host "    Then re-run this script, or install the tools manually." -ForegroundColor Yellow
} else {
    Write-Host "    Found: $($go.Source)" -ForegroundColor Green
    $packages = @(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "github.com/tomnomnom/waybackurls@latest",
        "github.com/Emoe/kxss@latest"
    )
    foreach ($pkg in $packages) {
        Write-Host "    go install $pkg"
        go install $pkg
        if ($LASTEXITCODE -ne 0) { Write-Host "[!] failed: $pkg" -ForegroundColor Yellow }
    }
    $gobin = Join-Path $env:USERPROFILE "go\bin"
    if ($env:PATH -notlike "*$gobin*") {
        Write-Host "[!] Add Go binaries to PATH:" -ForegroundColor Yellow
        Write-Host "    `$env:PATH += `\";$gobin`\"" -ForegroundColor Yellow
        Write-Host "    (or add $gobin permanently via System Properties > Environment Variables)" -ForegroundColor Yellow
    } else {
        Write-Host "    Go bin already in PATH" -ForegroundColor Green
    }
}

# Manual tools reminder
Write-Host "[*] Checking optional / manual tools..."
foreach ($tool in @("ffuf", "paramspider", "findomain", "amass")) {
    $found = Get-Command $tool -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "    [ok] $tool" -ForegroundColor Green
    } else {
        Write-Host "    [missing] $tool - install manually" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Manual install hints (Windows):" -ForegroundColor Cyan
Write-Host "  ffuf:        https://github.com/ffuf/ffuf/releases  (download ffuf_windows_amd64.zip)" -ForegroundColor White
Write-Host "  ParamSpider: pip install paramspider" -ForegroundColor White
Write-Host "  findomain:   https://github.com/findomain/findomain/releases" -ForegroundColor White
Write-Host "  amass:       https://github.com/owasp-amass/amass/releases" -ForegroundColor White
Write-Host ""
Write-Host "[+] Done. Run:  python bug.py" -ForegroundColor Green
