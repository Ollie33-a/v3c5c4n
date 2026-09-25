#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}           VecScan - Setup & Installation Script${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}[-] Go is not installed${NC}"
    echo "Please install Go 1.21 or higher from https://golang.org/dl/"
    exit 1
fi

echo -e "${GREEN}[+] Go version:${NC}"
go version
echo ""

# Get current directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo -e "${YELLOW}[*] Project directory: $PROJECT_DIR${NC}\n"

# Step 1: Initialize Go module if needed
if [ ! -f "go.mod" ]; then
    echo -e "${YELLOW}[*] Initializing Go module...${NC}"
    go mod init github.com/Ollie33-a/v3c5c4n
    echo -e "${GREEN}[+] Module initialized${NC}\n"
else
    echo -e "${GREEN}[+] go.mod already exists${NC}\n"
fi

# Step 2: Download dependencies
echo -e "${YELLOW}[*] Downloading dependencies...${NC}"
go get github.com/google/gopacket@v1.1.19
go get github.com/fatih/color@v1.16.0
go get golang.org/x/net@v0.19.0
go get golang.org/x/sys@v0.15.0
go get golang.org/x/sync@v0.5.0
echo -e "${GREEN}[+] Dependencies downloaded${NC}\n"

# Step 3: Tidy modules
echo -e "${YELLOW}[*] Tidying modules...${NC}"
go mod tidy
echo -e "${GREEN}[+] Modules tidy${NC}\n"

# Step 4: Build the application
echo -e "${YELLOW}[*] Building VecScan...${NC}"
if [ ! -d "cmd/vecscan" ]; then
    echo -e "${YELLOW}[!] Creating cmd/vecscan directory...${NC}"
    mkdir -p cmd/vecscan
fi

go build -o v3c5c4n ./cmd/vecscan/main.go
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Build successful!${NC}\n"
else
    echo -e "${RED}[-] Build failed!${NC}"
    exit 1
fi

# Step 5: Check if executable was created
if [ -f "v3c5c4n" ]; then
    chmod +x v3c5c4n
    echo -e "${GREEN}[+] Executable created: ./v3c5c4n${NC}\n"
else
    echo -e "${RED}[-] Executable not found${NC}"
    exit 1
fi

# Step 6: Verify the build
echo -e "${YELLOW}[*] Verifying build...${NC}"
./v3c5c4n -help > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Build verification successful${NC}\n"
fi

# Step 7: Summary
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] Installation Complete!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"

echo -e "${YELLOW}Quick Start:${NC}"
echo -e "  ${BLUE}Network Scan:${NC}"
echo -e "    sudo ./v3c5c4n -type network -target 192.168.1.1"
echo ""
echo -e "  ${BLUE}Web Vulnerability Scan:${NC}"
echo -e "    ./v3c5c4n -type web -target example.com"
echo ""
echo -e "  ${BLUE}Scan with Evasion:${NC}"
echo -e "    sudo ./v3c5c4n -type network -target 192.168.1.1 -evasion"
echo ""
echo -e "  ${BLUE}Help:${NC}"
echo -e "    ./v3c5c4n -help"
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"