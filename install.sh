#!/usr/bin/env bash
# Bug Hunter installer. Safe to re-run.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Checking Python..."
if ! command -v python3 >/dev/null 2>&1; then
  echo "[-] python3 not found. Install Python 3.9+ first."; exit 1
fi
if ! python3 -c "import tkinter" >/dev/null 2>&1; then
  echo "[!] tkinter is missing. Install it with your OS package manager, e.g.:"
  echo "      Debian/Ubuntu/Kali: sudo apt install python3-tk"
  echo "      Fedora:             sudo dnf install python3-tkinter"
  echo "      macOS (brew):       brew install python-tk"
fi

echo "[*] Installing Python dependencies (Pillow)..."
if ! python3 -m pip install -r "$SCRIPT_DIR/requirements.txt"; then
  echo "[!] pip refused to install system-wide (PEP 668 / externally-managed environment)."
  echo "    Use a virtual environment instead:"
  echo "      python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt"
fi

echo "[*] Installing Go tools..."
if ! command -v go >/dev/null 2>&1; then
  echo "[-] Go is not installed (https://go.dev/doc/install). Skipping Go tools."
else
  for pkg in \
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    github.com/projectdiscovery/httpx/cmd/httpx@latest \
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    github.com/tomnomnom/waybackurls@latest \
    github.com/Emoe/kxss@latest; do
    echo "    go install $pkg"
    go install "$pkg" || echo "[!] failed: $pkg"
  done
  case ":$PATH:" in
    *":$HOME/go/bin:"*) ;;
    *) echo "[!] Add Go binaries to PATH:  export PATH=\$PATH:\$HOME/go/bin" ;;
  esac
fi

echo "[*] Checking optional tools..."
for tool in ffuf paramspider findomain amass; do
  command -v "$tool" >/dev/null 2>&1 && echo "    [ok] $tool" || echo "    [missing] $tool - install it manually (see README)"
done

echo "[+] Done. Run:  python3 bug.py"
