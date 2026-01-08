#!/bin/bash

#######################################################
#  Security One IDS/IPS Agent - 一鍵部署腳本
#######################################################

set -e

# 顏色輸出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     Security One IDS/IPS Agent - 一鍵部署腳本             ║"
    echo "║                   version 1.0.0                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${CYAN}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# 檢查必要工具
check_requirements() {
    print_info "檢查系統需求..."
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker 未安裝。請先安裝 Docker。"
        echo "  安裝指南: https://docs.docker.com/get-docker/"
        exit 1
    fi
    print_step "Docker 已安裝"
    
    if ! command -v docker compose &> /dev/null && ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose 未安裝。請先安裝 Docker Compose。"
        exit 1
    fi
    print_step "Docker Compose 已安裝"
    
    if ! command -v git &> /dev/null; then
        print_error "Git 未安裝。請先安裝 Git。"
        exit 1
    fi
    print_step "Git 已安裝"
}

# 取得使用者輸入
get_config() {
    echo ""
    print_info "請提供以下資訊來設定 Agent："
    echo ""
    
    # WAF URL
    read -p "請輸入 WAF 管理端 URL (例如: https://waf.example.com): " WAF_URL
    if [[ -z "$WAF_URL" ]]; then
        print_error "WAF URL 不能為空"
        exit 1
    fi
    
    # Agent Token
    read -p "請輸入從 WAF 取得的 Agent Token: " AGENT_TOKEN
    if [[ -z "$AGENT_TOKEN" ]]; then
        print_error "Agent Token 不能為空"
        exit 1
    fi
    
    # Agent Name
    read -p "請輸入此 Agent 的名稱 (例如: Web-Server-01): " AGENT_NAME
    if [[ -z "$AGENT_NAME" ]]; then
        AGENT_NAME="ids-agent-$(hostname)"
        print_warning "使用預設名稱: $AGENT_NAME"
    fi
    
    # Port
    read -p "請輸入 Agent 監聽埠口 [預設: 8003]: " AGENT_PORT
    AGENT_PORT=${AGENT_PORT:-8003}
    
    # Log Paths
    echo ""
    print_info "日誌監控設定 (可監控多個目錄)"
    echo "  預設已監控: /var/log/nginx, /var/log/apache2"
    echo ""
    LOG_PATHS=()
    while true; do
        read -p "請輸入額外的日誌目錄路徑 (留空跳過): " LOG_PATH
        if [[ -z "$LOG_PATH" ]]; then
            break
        fi
        if [[ -d "$LOG_PATH" ]]; then
            LOG_PATHS+=("$LOG_PATH")
            print_step "已添加: $LOG_PATH"
        else
            print_warning "目錄不存在: $LOG_PATH"
        fi
    done
    
    echo ""
    print_info "設定摘要:"
    echo "  WAF URL:     $WAF_URL"
    echo "  Agent Token: ${AGENT_TOKEN:0:20}..."
    echo "  Agent Name:  $AGENT_NAME"
    echo "  Port:        $AGENT_PORT"
    if [[ ${#LOG_PATHS[@]} -gt 0 ]]; then
        echo "  額外日誌目錄:"
        for path in "${LOG_PATHS[@]}"; do
            echo "    - $path"
        done
    fi
    echo ""
    
    read -p "確認以上設定正確? [Y/n]: " CONFIRM
    CONFIRM=${CONFIRM:-Y}
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        print_warning "已取消安裝"
        exit 0
    fi
}

# 下載或更新專案
download_project() {
    INSTALL_DIR="${INSTALL_DIR:-/opt/security-one-ids}"
    
    print_info "準備安裝目錄: $INSTALL_DIR"
    
    if [[ -d "$INSTALL_DIR" ]]; then
        print_warning "目錄已存在，正在更新..."
        cd "$INSTALL_DIR"
        git pull origin main || git pull origin master || true
    else
        print_info "正在下載 Security One IDS/IPS Agent..."
        sudo mkdir -p "$INSTALL_DIR"
        sudo chown $USER:$USER "$INSTALL_DIR"
        git clone https://github.com/vito1317/security-one-ids.git "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
    
    print_step "專案已就緒"
}

# 建立環境設定檔
create_env_file() {
    print_info "正在建立環境設定檔..."
    
    # 生成 APP_KEY
    APP_KEY="base64:$(openssl rand -base64 32)"
    
    cat > "$INSTALL_DIR/.env" << EOF
APP_NAME="Security One IDS/IPS Agent"
APP_ENV=production
APP_KEY=$APP_KEY
APP_DEBUG=false
APP_URL=http://localhost:$AGENT_PORT

# WAF 連線設定
WAF_URL=$WAF_URL
AGENT_TOKEN=$AGENT_TOKEN
AGENT_NAME=$AGENT_NAME

# 資料庫設定
DB_CONNECTION=sqlite
DB_DATABASE=/var/www/html/database/database.sqlite

# 日誌設定
LOG_CHANNEL=daily
LOG_LEVEL=info
EOF

    print_step "環境設定檔已建立"
}

# 建立 docker-compose.yml (如果需要自訂)
create_docker_compose() {
    print_info "正在建立 Docker Compose 設定..."
    
    # 如果已存在 docker-compose.yml 且埠口是預設的，就不覆蓋
    if [[ -f "$INSTALL_DIR/docker-compose.yml" && "$AGENT_PORT" == "8003" ]]; then
        print_step "使用現有的 docker-compose.yml"
        return
    fi
    
    # Build volume mounts for log directories
    VOLUME_MOUNTS="      - ./database:/var/www/html/database
      - ./storage:/var/www/html/storage
      # Host log directories (read-only)
      - /var/log/nginx:/var/log/host-nginx:ro
      - /var/log/apache2:/var/log/host-apache2:ro"
    
    # Add custom log paths
    LOG_INDEX=1
    for path in "${LOG_PATHS[@]}"; do
        VOLUME_MOUNTS="$VOLUME_MOUNTS
      - $path:/var/log/custom-logs-$LOG_INDEX:ro"
        LOG_INDEX=$((LOG_INDEX + 1))
    done
    
    cat > "$INSTALL_DIR/docker-compose.yml" << EOF
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: security-one-ids
    restart: unless-stopped
    ports:
      - "${AGENT_PORT}:80"
    environment:
      - APP_ENV=production
      - APP_DEBUG=false
    env_file:
      - .env
    volumes:
$VOLUME_MOUNTS
    extra_hosts:
      - "host.docker.internal:host-gateway"
    networks:
      - security-one-ids-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  security-one-ids-network:
    driver: bridge
EOF

    print_step "Docker Compose 設定已建立"
}

# 建立必要目錄
create_directories() {
    print_info "正在建立必要目錄..."
    
    mkdir -p "$INSTALL_DIR/database"
    mkdir -p "$INSTALL_DIR/storage/logs"
    mkdir -p "$INSTALL_DIR/storage/framework/sessions"
    mkdir -p "$INSTALL_DIR/storage/framework/views"
    mkdir -p "$INSTALL_DIR/storage/framework/cache"
    
    # 建立 SQLite 資料庫檔案
    touch "$INSTALL_DIR/database/database.sqlite"
    
    chmod -R 775 "$INSTALL_DIR/storage"
    chmod -R 775 "$INSTALL_DIR/database"
    
    print_step "目錄結構已建立"
}

# 建構並啟動容器
start_containers() {
    print_info "正在建構 Docker 映像..."
    cd "$INSTALL_DIR"
    
    docker compose build --no-cache
    print_step "Docker 映像建構完成"
    
    print_info "正在啟動容器..."
    docker compose up -d
    print_step "容器已啟動"
    
    # 等待容器就緒
    print_info "等待服務就緒..."
    sleep 5
    
    # 執行資料庫遷移
    print_info "正在執行資料庫遷移..."
    docker compose exec -T app php artisan migrate --force || true
    print_step "資料庫已就緒"
    
    # 種子預設簽章
    print_info "正在安裝預設 IDS 簽章..."
    docker compose exec -T app php artisan ids:seed-signatures || true
    print_step "預設簽章已安裝"
    
    # 與 WAF Hub 進行初始同步
    print_info "正在與 WAF Hub 同步..."
    docker compose exec -T app php artisan waf:sync --register
    if [ $? -eq 0 ]; then
        print_step "WAF 同步完成"
    else
        print_warning "WAF 同步失敗，請稍後手動執行: docker compose exec app php artisan waf:sync --register"
    fi
}

# 驗證安裝
verify_installation() {
    print_info "正在驗證安裝..."
    
    # 檢查容器狀態
    if docker compose ps | grep -q "Up"; then
        print_step "容器運行正常"
    else
        print_error "容器未正常運行"
        docker compose logs
        exit 1
    fi
    
    # 檢查健康狀態 (如果有 health endpoint)
    sleep 3
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$AGENT_PORT" | grep -q "200\|302"; then
        print_step "HTTP 服務正常"
    else
        print_warning "HTTP 服務可能需要更多時間啟動"
    fi
}

# 顯示完成資訊
show_completion() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          🎉 Security One IDS/IPS Agent 部署完成！          ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}安裝目錄:${NC} $INSTALL_DIR"
    echo -e "  ${CYAN}服務網址:${NC} http://localhost:$AGENT_PORT"
    echo -e "  ${CYAN}Agent 名稱:${NC} $AGENT_NAME"
    echo ""
    echo -e "  ${YELLOW}常用指令:${NC}"
    echo "    cd $INSTALL_DIR"
    echo "    docker compose logs -f          # 查看日誌"
    echo "    docker compose restart          # 重啟服務"
    echo "    docker compose down             # 停止服務"
    echo ""
    echo -e "  ${YELLOW}WAF 同步指令:${NC}"
    echo "    docker compose exec app php artisan waf:sync          # 手動同步"
    echo "    docker compose exec app php artisan waf:sync --register  # 重新註冊"
    echo ""
    echo -e "  ${CYAN}下一步:${NC}"
    echo "    1. 前往 WAF 管理介面確認 Agent 已連線"
    echo "    2. 在 WAF 設定 IDS 規則並同步至此 Agent"
    echo ""
}

# 快速部署模式 (使用命令行參數)
quick_deploy() {
    WAF_URL="$1"
    AGENT_TOKEN="$2"
    AGENT_NAME="${3:-ids-agent-$(hostname)}"
    AGENT_PORT="${4:-8003}"
    
    if [[ -z "$WAF_URL" || -z "$AGENT_TOKEN" ]]; then
        echo "使用方法: $0 --quick <WAF_URL> <AGENT_TOKEN> [AGENT_NAME] [PORT]"
        exit 1
    fi
}

# 主程式
main() {
    print_banner
    
    # 檢查是否為快速模式
    if [[ "$1" == "--quick" || "$1" == "-q" ]]; then
        shift
        quick_deploy "$@"
    else
        check_requirements
        get_config
    fi
    
    download_project
    create_env_file
    create_docker_compose
    create_directories
    start_containers
    verify_installation
    show_completion
}

# 執行
main "$@"
