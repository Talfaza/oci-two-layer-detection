#!/bin/bash

# Define color codes for clean output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "Starting Environment Validation for OCI Steganography Research...\n"

check_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        echo -e "${GREEN}[PASS]${NC} $1 is installed and in PATH."
    else
        echo -e "${RED}[FAIL]${NC} $1 is missing or not in PATH."
    fi
}

echo -e "=== 1. System & Compilation Stack ==="
for cmd in gcc make clang llvm-objcopy git; do
    check_cmd "$cmd"
done

echo -e "\n=== 2. Kernel Dependencies (eBPF CO-RE) ==="
if [ -d "/usr/src/kernels/$(uname -r)" ]; then
    echo -e "${GREEN}[PASS]${NC} kernel-devel for $(uname -r) is present."
else
    echo -e "${RED}[FAIL]${NC} kernel-devel for $(uname -r) is missing."
fi

echo -e "\n=== 3. Container Tooling ==="
for cmd in docker skopeo go crane umoci dive; do
    check_cmd "$cmd"
done

echo -e "\n=== 4. eBPF Toolchain ==="
check_cmd bpftrace
if python3 -c "import bcc" 2>/dev/null; then
    echo -e "${GREEN}[PASS]${NC} python3-bcc module is installed."
else
    echo -e "${RED}[FAIL]${NC} python3-bcc module is missing."
fi

if [ -d "$HOME/libbpf-bootstrap" ]; then
    echo -e "${GREEN}[PASS]${NC} libbpf-bootstrap found at $HOME/libbpf-bootstrap."
else
    echo -e "${YELLOW}[WARN]${NC} libbpf-bootstrap not found. Ensure you cloned it into your home directory."
fi

echo -e "\n=== 5. Python Static Analysis Stack ==="
VENV_DIR="$HOME/stego-research/venv"
if [ -f "$VENV_DIR/bin/python3" ]; then
    echo -e "${GREEN}[PASS]${NC} Virtual environment found at $VENV_DIR."
    for mod in numpy scipy matplotlib pandas; do
        if "$VENV_DIR/bin/python3" -c "import $mod" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $mod installed"
        else
            echo -e "  ${RED}✗${NC} $mod missing"
        fi
    done
else
    echo -e "${YELLOW}[WARN]${NC} Virtual environment not found at $VENV_DIR. Checking globally..."
    for mod in numpy scipy matplotlib pandas; do
        if python3 -c "import $mod" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $mod installed globally"
        else
            echo -e "  ${RED}✗${NC} $mod missing globally"
        fi
    done
fi

echo -e "\n=== 6. External Baselines ==="
check_cmd falco
check_cmd tetragon

echo -e "\n=== 7. Service Health ==="
if systemctl is-active --quiet docker; then
    echo -e "${GREEN}[PASS]${NC} Docker service is active."
else
    echo -e "${RED}[FAIL]${NC} Docker service is not running. (Run: sudo systemctl start docker)"
fi

if systemctl list-units --type=service --state=active | grep -q falco; then
    FALCO_SVC=$(systemctl list-units --type=service --state=active | grep falco | awk '{print $1}')
    echo -e "${GREEN}[PASS]${NC} Falco service ($FALCO_SVC) is active."
else
    echo -e "${YELLOW}[WARN]${NC} No active Falco systemd service found."
fi

echo -e "\nValidation Complete. Go build!"
