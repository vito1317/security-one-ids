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

if ! command -v composer &> /dev/null; then
    echo -e "${YELLOW}Installing Composer...${NC}"
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
fi
echo -e "${GREEN}✅ Composer installed${NC}"

# ClamAV Installation Function
install_clamav() {
    echo -e "\n${CYAN}🛡️  Installing ClamAV Antivirus...${NC}"
    
    if [ "$OS" = "macos" ]; then
        # macOS - use Homebrew
        if command -v brew &> /dev/null; then
            # Run brew as the original user (not root)
            ORIGINAL_USER="${SUDO_USER:-$USER}"
            sudo -u "$ORIGINAL_USER" brew install clamav 2>/dev/null || brew install clamav
            
            # Configure freshclam
            CLAMAV_CONF_DIR="/opt/homebrew/etc/clamav"
            if [ ! -d "$CLAMAV_CONF_DIR" ]; then
                CLAMAV_CONF_DIR="/usr/local/etc/clamav"
            fi
            
            if [ -f "$CLAMAV_CONF_DIR/freshclam.conf.sample" ] && [ ! -f "$CLAMAV_CONF_DIR/freshclam.conf" ]; then
                cp "$CLAMAV_CONF_DIR/freshclam.conf.sample" "$CLAMAV_CONF_DIR/freshclam.conf"
                sed -i '' 's/^Example/#Example/' "$CLAMAV_CONF_DIR/freshclam.conf" 2>/dev/null || true
            fi
        else
            echo -e "${RED}Homebrew not found. Please install Homebrew first or install ClamAV manually.${NC}"
            return 1
        fi
    elif [ "$OS" = "debian" ]; then
        apt-get update -qq
        apt-get install -y clamav clamav-daemon
        systemctl stop clamav-freshclam 2>/dev/null || true
    elif [ "$OS" = "redhat" ]; then
        if command -v dnf &> /dev/null; then
            dnf install -y clamav clamav-update clamd
        else
            yum install -y clamav clamav-update clamd
        fi
    else
        echo -e "${YELLOW}Please install ClamAV manually for your distribution.${NC}"
        return 1
    fi
    
    # Update virus definitions
    echo -e "${CYAN}📥 Updating virus definitions...${NC}"
    freshclam 2>/dev/null || true
    
    echo -e "${GREEN}✅ ClamAV installed and updated${NC}"
    return 0
}

# Ask about ClamAV installation
INSTALL_CLAMAV="${INSTALL_CLAMAV:-}"
if [ -z "$INSTALL_CLAMAV" ]; then
    echo -e "\n${YELLOW}🛡️  Install ClamAV Antivirus? (Optional add-on)${NC}"
    echo -e "   ClamAV can scan your system for malware and viruses."
    read -p "   Install ClamAV? [y/N]: " CLAMAV_CHOICE
    if [[ "$CLAMAV_CHOICE" =~ ^[Yy]$ ]]; then
        INSTALL_CLAMAV="yes"
    fi
fi

if [ "$INSTALL_CLAMAV" = "yes" ]; then
    install_clamav || echo -e "${YELLOW}⚠️  ClamAV installation skipped${NC}"
fi

# Create directories
echo -e "\n${CYAN}📂 Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"

# Check for existing configuration BEFORE downloading or deleting files
EXISTING_ENV="$INSTALL_DIR/.env"
if [ -f "$EXISTING_ENV" ] && [ -z "$WAF_HUB_URL" ] && [ -z "$AGENT_TOKEN" ]; then
    echo -e "${YELLOW}📋 Found existing configuration, loading previous settings...${NC}"
    
    # Read existing values from .env file
    EXISTING_WAF_URL=$(grep "^WAF_URL=" "$EXISTING_ENV" | tr -d '\r' | cut -d'=' -f2- | tr -d '"' | tr -d "'")
    EXISTING_TOKEN=$(grep "^AGENT_TOKEN=" "$EXISTING_ENV" | tr -d '\r' | cut -d'=' -f2- | tr -d '"' | tr -d "'")
    EXISTING_NAME=$(grep "^AGENT_NAME=" "$EXISTING_ENV" | tr -d '\r' | cut -d'=' -f2- | tr -d '"' | tr -d "'")
    
    # Use existing values if found
    if [ -n "$EXISTING_WAF_URL" ]; then
        WAF_HUB_URL="$EXISTING_WAF_URL"
        echo -e "  WAF Hub URL: ${GREEN}$WAF_HUB_URL${NC}"
    fi
    
    if [ -n "$EXISTING_TOKEN" ]; then
        AGENT_TOKEN="$EXISTING_TOKEN"
        echo -e "  Agent Token: ${GREEN}(using existing token)${NC}"
    fi
    
    if [ -n "$EXISTING_NAME" ]; then
        AGENT_NAME="$EXISTING_NAME"
        echo -e "  Agent Name: ${GREEN}$AGENT_NAME${NC}"
    fi
    
    echo -e "${GREEN}✅ Using existing configuration${NC}"
fi

# Download IDS Agent using git clone (allows git pull for updates)
echo -e "\n${CYAN}📥 Downloading Security One IDS Agent...${NC}"

# Check if git is available
if command -v git &> /dev/null; then
    # Backup existing .env if exists
    if [ -f "$INSTALL_DIR/.env" ]; then
        cp "$INSTALL_DIR/.env" /tmp/security-one-ids-env-backup
    fi
    
    # Remove old installation but keep data
    rm -rf "$INSTALL_DIR/.git" "$INSTALL_DIR/app" "$INSTALL_DIR/config" "$INSTALL_DIR/routes" "$INSTALL_DIR/resources" 2>/dev/null
    
    # Clone or update repository
    if [ -d "$INSTALL_DIR/.git" ]; then
        cd "$INSTALL_DIR"
        git pull origin main
    else
        git clone --depth 1 https://github.com/vito1317/security-one-ids.git /tmp/security-one-ids-clone
        cp -r /tmp/security-one-ids-clone/* "$INSTALL_DIR/"
        cp -r /tmp/security-one-ids-clone/.git "$INSTALL_DIR/"
        rm -rf /tmp/security-one-ids-clone
    fi
    
    # Restore .env if was backed up
    if [ -f /tmp/security-one-ids-env-backup ]; then
        cp /tmp/security-one-ids-env-backup "$INSTALL_DIR/.env"
        rm /tmp/security-one-ids-env-backup
    fi
    
    echo -e "${GREEN}✅ IDS Agent downloaded via Git (supports updates)${NC}"
else
    # Fallback to zip download if git is not available
    echo -e "${YELLOW}Git not found, using zip download (git pull won't work)${NC}"
    cd /tmp
    rm -rf security-one-ids-main security-one-ids.zip
    curl -fsSL -o security-one-ids.zip https://github.com/vito1317/security-one-ids/archive/refs/heads/main.zip
    unzip -q security-one-ids.zip
    cp -r security-one-ids-main/* "$INSTALL_DIR/"
    rm -rf security-one-ids-main security-one-ids.zip
    echo -e "${GREEN}✅ IDS Agent downloaded${NC}"
fi

# Install Composer dependencies (skip scripts to avoid .env loading issues)
echo -e "\n${CYAN}📦 Installing dependencies...${NC}"
cd "$INSTALL_DIR"

# Remove any existing .env to prevent parsing errors during composer install
rm -f "$INSTALL_DIR/.env"

# Use --no-scripts to prevent artisan package:discover from running before .env is created
export COMPOSER_ALLOW_SUPERUSER=1
composer install --no-dev --optimize-autoloader --no-interaction --no-scripts 2>/dev/null || composer install --no-dev --no-interaction --no-scripts

# Configure environment
echo -e "\n${CYAN}⚙️  Configuring IDS Agent...${NC}"



# Prompt for configuration if still not set
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

WAF_URL="$WAF_HUB_URL"
AGENT_TOKEN="$AGENT_TOKEN"
AGENT_NAME="$AGENT_NAME"

OLLAMA_URL=https://ollama.futron-life.com
OLLAMA_MODEL=sentinel-security
AI_DETECTION_ENABLED=true
AI_TIMEOUT=30

LOG_CHANNEL=daily
LOG_LEVEL=info
EOF

echo -e "${GREEN}✅ Configuration saved${NC}"

# Create SQLite database and run migrations
echo -e "\n${CYAN}🗄️  Setting up database...${NC}"
touch "$INSTALL_DIR/database/database.sqlite"
cd "$INSTALL_DIR"
php artisan migrate --force 2>/dev/null || echo -e "${YELLOW}⚠️  Migration skipped (may already exist)${NC}"
php artisan package:discover --ansi 2>/dev/null || true

# Set permissions (macOS uses 'wheel' group, Linux uses 'root')
if [ "$OS" = "macos" ]; then
    chown -R root:wheel "$INSTALL_DIR"
else
    chown -R root:root "$INSTALL_DIR"
fi
chmod -R 755 "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/.env"
chmod 666 "$INSTALL_DIR/database/database.sqlite"

# Create systemd service (Linux) or launchd plist (macOS)
echo -e "\n${CYAN}🔧 Creating system service...${NC}"

if [ "$OS" = "macos" ]; then
    # macOS launchd - detect PHP path
    PHP_PATH=$(which php 2>/dev/null || echo "/usr/local/bin/php")
    if [ ! -f "$PHP_PATH" ]; then
        PHP_PATH="/opt/homebrew/bin/php"
    fi
    if [ ! -f "$PHP_PATH" ]; then
        PHP_PATH="/usr/bin/php"
    fi
    
    # Create both scan and sync plist files
    cat > /Library/LaunchDaemons/com.securityone.ids.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.securityone.ids</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PHP_PATH</string>
        <string>$INSTALL_DIR/artisan</string>
        <string>desktop:scan</string>
        <string>--full</string>
        <string>--report</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/output.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>
</dict>
</plist>
EOF
    
    # Create heartbeat sync plist (runs every 60 seconds)
    cat > /Library/LaunchDaemons/com.securityone.ids.sync.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.securityone.ids.sync</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PHP_PATH</string>
        <string>$INSTALL_DIR/artisan</string>
        <string>waf:sync</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>StartInterval</key>
    <integer>60</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/sync.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/sync-error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>
</dict>
</plist>
EOF
    
    launchctl load /Library/LaunchDaemons/com.securityone.ids.plist
    launchctl load /Library/LaunchDaemons/com.securityone.ids.sync.plist
    echo -e "${GREEN}✅ macOS LaunchDaemons created (scan + sync)${NC}"
    
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
OnBootSec=2min
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
ExecStart=/usr/bin/php $INSTALL_DIR/artisan desktop:scan --full
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

# Run initial scan with full AI analysis
echo -e "\n${CYAN}🔍 Running initial security scan...${NC}"
php artisan desktop:scan --full --report

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
