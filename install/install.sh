#!/bin/bash
# Security One IDS Agent - macOS/Linux Installation Script
# One-line install:
# curl -fsSL https://raw.githubusercontent.com/vito1317/security-one-ids/main/install/install.sh | sudo bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}
╔═══════════════════════════════════════════════════╗
║   Security One IDS Agent - macOS/Linux Installer  ║
╚═══════════════════════════════════════════════════╝
${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Please run as root (sudo)${NC}"
    exit 1
fi

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ -f /etc/debian_version ]]; then
    OS="debian"
elif [[ -f /etc/redhat-release ]]; then
    OS="redhat"
else
    OS="linux"
fi

echo -e "${YELLOW}🖥️  Detected OS: $OS${NC}"

# Configuration
INSTALL_DIR="/opt/security-one-ids"
DATA_DIR="/var/lib/security-one-ids"
LOG_DIR="/var/log/security-one-ids"
SERVICE_NAME="security-one-ids"

# Get configuration from user or environment
WAF_HUB_URL="${WAF_HUB_URL:-}"
AGENT_TOKEN="${AGENT_TOKEN:-}"
AGENT_NAME="${AGENT_NAME:-$(hostname)}"

echo -e "${YELLOW}📁 Installation Directory: $INSTALL_DIR${NC}"
echo -e "${YELLOW}📁 Data Directory: $DATA_DIR${NC}"

# Install prerequisites
echo -e "\n${CYAN}🔍 Installing prerequisites...${NC}"

install_php() {
    case $OS in
        macos)
            if ! command -v brew &> /dev/null; then
                echo -e "${YELLOW}Installing Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install php composer
            ;;
        debian)
            apt-get update
            apt-get install -y php php-cli php-curl php-json php-mbstring php-xml composer git
            ;;
        redhat)
            yum install -y epel-release
            yum install -y php php-cli php-curl php-json php-mbstring php-xml composer git
            ;;
        *)
            echo -e "${RED}Unsupported OS. Please install PHP 8.0+ manually.${NC}"
            exit 1
            ;;
    esac
}

# Check PHP
if ! command -v php &> /dev/null; then
    echo -e "${YELLOW}PHP not found. Installing...${NC}"
    install_php
fi

PHP_VERSION=$(php -r "echo PHP_VERSION;")
echo -e "${GREEN}✅ PHP $PHP_VERSION installed${NC}"

# Check Composer
if ! command -v composer &> /dev/null; then
    echo -e "${YELLOW}Installing Composer...${NC}"
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
fi
echo -e "${GREEN}✅ Composer installed${NC}"

# Create directories
echo -e "\n${CYAN}📂 Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"

# Download IDS Agent
echo -e "\n${CYAN}📥 Downloading Security One IDS Agent...${NC}"
cd /tmp
rm -rf security-one-ids-main security-one-ids.zip

curl -fsSL -o security-one-ids.zip https://github.com/vito1317/security-one-ids/archive/refs/heads/main.zip
unzip -q security-one-ids.zip
cp -r security-one-ids-main/* "$INSTALL_DIR/"
rm -rf security-one-ids-main security-one-ids.zip

echo -e "${GREEN}✅ IDS Agent downloaded${NC}"

# Install Composer dependencies
echo -e "\n${CYAN}📦 Installing dependencies...${NC}"
cd "$INSTALL_DIR"
composer install --no-dev --optimize-autoloader --no-interaction 2>/dev/null || composer install --no-dev --no-interaction

# Configure environment
echo -e "\n${CYAN}⚙️  Configuring IDS Agent...${NC}"

# Prompt for configuration if not set
if [ -z "$WAF_HUB_URL" ]; then
    read -p "Enter WAF Hub URL (e.g., https://waf.example.com): " WAF_HUB_URL
fi

if [ -z "$AGENT_TOKEN" ]; then
    read -p "Enter Agent Token: " AGENT_TOKEN
fi

cat > "$INSTALL_DIR/.env" << EOF
APP_NAME="Security One IDS"
APP_ENV=production
APP_DEBUG=false

WAF_URL=$WAF_HUB_URL
AGENT_TOKEN=$AGENT_TOKEN
AGENT_NAME=$AGENT_NAME

OLLAMA_URL=https://ollama.futron-life.com
OLLAMA_MODEL=sentinel-security
AI_DETECTION_ENABLED=true
AI_TIMEOUT=30

LOG_CHANNEL=daily
LOG_LEVEL=info
EOF

echo -e "${GREEN}✅ Configuration saved${NC}"

# Set permissions (macOS uses 'wheel' group, Linux uses 'root')
if [ "$OS" = "macos" ]; then
    chown -R root:wheel "$INSTALL_DIR"
else
    chown -R root:root "$INSTALL_DIR"
fi
chmod -R 755 "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/.env"

# Create systemd service (Linux) or launchd plist (macOS)
echo -e "\n${CYAN}🔧 Creating system service...${NC}"

if [ "$OS" = "macos" ]; then
    # macOS launchd
    cat > /Library/LaunchDaemons/com.securityone.ids.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.securityone.ids</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/php</string>
        <string>$INSTALL_DIR/artisan</string>
        <string>desktop:scan</string>
        <string>--report</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/output.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/error.log</string>
</dict>
</plist>
EOF
    
    launchctl load /Library/LaunchDaemons/com.securityone.ids.plist
    echo -e "${GREEN}✅ macOS LaunchDaemon created${NC}"
    
else
    # Linux systemd
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=Security One IDS Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/php $INSTALL_DIR/artisan schedule:work
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Create timer for periodic scans
    cat > /etc/systemd/system/$SERVICE_NAME-scan.timer << EOF
[Unit]
Description=Security One IDS Periodic Scan

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

    cat > /etc/systemd/system/$SERVICE_NAME-scan.service << EOF
[Unit]
Description=Security One IDS Scan

[Service]
Type=oneshot
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/php $INSTALL_DIR/artisan desktop:scan --report
EOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    systemctl enable $SERVICE_NAME-scan.timer
    systemctl start $SERVICE_NAME
    systemctl start $SERVICE_NAME-scan.timer
    
    echo -e "${GREEN}✅ Systemd service created${NC}"
fi

# Register with WAF Hub
echo -e "\n${CYAN}📡 Registering with WAF Hub...${NC}"
cd "$INSTALL_DIR"
php artisan waf:sync --register || echo -e "${YELLOW}⚠️  Registration will retry on next scan${NC}"

# Run initial scan
echo -e "\n${CYAN}🔍 Running initial security scan...${NC}"
php artisan desktop:scan

# Create convenience commands
echo -e "\n${CYAN}🔧 Creating convenience commands...${NC}"

cat > /usr/local/bin/ids-scan << 'EOF'
#!/bin/bash
cd /opt/security-one-ids && php artisan desktop:scan "$@"
EOF
chmod +x /usr/local/bin/ids-scan

cat > /usr/local/bin/ids-status << 'EOF'
#!/bin/bash
if [[ "$OSTYPE" == "darwin"* ]]; then
    launchctl list | grep securityone
else
    systemctl status security-one-ids
fi
EOF
chmod +x /usr/local/bin/ids-status

echo -e "${GREEN}
╔═══════════════════════════════════════════════════╗
║      ✅ Installation Complete!                     ║
╠═══════════════════════════════════════════════════╣
║  Install Path: $INSTALL_DIR
║  Log Path:     $LOG_DIR
║  
║  Commands:
║    ids-scan         Quick security scan
║    ids-scan --full  Full AI analysis
║    ids-status       Check service status
║
║  Manual Commands:
║    cd $INSTALL_DIR
║    php artisan desktop:scan
║    php artisan desktop:scan --full --report
║
╚═══════════════════════════════════════════════════╝
${NC}"
