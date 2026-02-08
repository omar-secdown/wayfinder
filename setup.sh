#!/bin/bash

echo "=============================================="
echo "   Wayfinder v4.0 - Setup Script"
echo "=============================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Go is installed
echo "[*] Checking for Go installation..."
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}[✓]${NC} Go is installed: $GO_VERSION"
else
    echo -e "${RED}[✗]${NC} Go is not installed!"
    echo "[!] Please install Go from: https://go.dev/doc/install"
    exit 1
fi

# Check if Python3 is installed
echo "[*] Checking for Python3 installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}[✓]${NC} Python3 is installed: $PYTHON_VERSION"
else
    echo -e "${RED}[✗]${NC} Python3 is not installed!"
    echo "[!] Please install Python3"
    exit 1
fi

# Add Go bin to PATH if not already
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    echo "[*] Adding Go bin to PATH..."
    export PATH=$PATH:$HOME/go/bin
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    echo -e "${GREEN}[✓]${NC} Go bin added to PATH"
fi

# Install Go tools
echo ""
echo "=============================================="
echo "   Installing Required Go Tools"
echo "=============================================="
echo ""

echo "[1/5] Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} httpx installed successfully"
else
    echo -e "${RED}[✗]${NC} httpx installation failed"
fi

echo ""
echo "[2/5] Installing alterx..."
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} alterx installed successfully"
else
    echo -e "${RED}[✗]${NC} alterx installation failed"
fi

echo ""
echo "[3/5] Installing shuffledns..."
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} shuffledns installed successfully"
else
    echo -e "${RED}[✗]${NC} shuffledns installation failed"
fi

echo ""
echo "[4/5] Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} subfinder installed successfully"
else
    echo -e "${RED}[✗]${NC} subfinder installation failed"
fi

echo ""
echo "[5/5] Installing anew..."
go install -v github.com/tomnomnom/anew@latest
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} anew installed successfully"
else
    echo -e "${RED}[✗]${NC} anew installation failed"
fi

# Install Python dependencies
echo ""
echo "=============================================="
echo "   Installing Python Dependencies"
echo "=============================================="
echo ""

echo "[*] Installing Python requirements..."
pip install --break-system-packages -r requirements.txt 2>/dev/null || pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} Python dependencies installed"
else
    echo -e "${RED}[✗]${NC} Python dependencies installation failed"
fi

# Install Shodan
echo ""
echo "[*] Installing Shodan CLI..."
pip install shodan --break-system-packages 2>/dev/null || pip install shodan

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} Shodan installed successfully"
    echo -e "${YELLOW}[!]${NC} Don't forget to configure Shodan with: shodan init YOUR_API_KEY"
else
    echo -e "${RED}[✗]${NC} Shodan installation failed"
fi

# Run config validation
echo ""
echo "=============================================="
echo "   Validating Configuration"
echo "=============================================="
echo ""

python3 config.py

# Final message
echo ""
echo "=============================================="
echo "   Setup Complete!"
echo "=============================================="
echo ""
echo -e "${GREEN}[✓]${NC} All tools installed"
echo ""
echo "Next steps:"
echo "1. Copy .env.example to .env and add your API keys"
echo "   cp .env.example .env"
echo "2. Initialize Shodan: shodan init YOUR_API_KEY"
echo "3. Run validation: python3 config.py"
echo "4. Start scanning: python3 main.py -u example.com"
echo ""
echo "For more information, see README.md"
echo ""
