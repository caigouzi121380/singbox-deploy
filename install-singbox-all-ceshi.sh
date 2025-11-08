#!/usr/bin/env bash
set -euo pipefail

# -----------------------
# 颜色输出函数
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

# -----------------------
# 检测系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_ID_LIKE="${ID_LIKE:-}"
    else
        OS_ID=""
        OS_ID_LIKE=""
    fi

    if echo "$OS_ID $OS_ID_LIKE" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "$OS_ID $OS_ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "$OS_ID $OS_ID_LIKE" | grep -Ei "centos|rhel|fedora" >/dev/null; then
        OS="redhat"
    else
        OS="unknown"
    fi
}

detect_os
info "检测到系统: $OS (${OS_ID:-unknown})"

# -----------------------
# 检查 root 权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        err "此脚本需要 root 权限运行"
        err "请使用: sudo bash -c \"\$(curl -fsSL ...)\" 或切换到 root 用户"
        exit 1
    fi
}

check_root

# -----------------------
# 安装依赖
install_deps() {
    info "安装系统依赖..."
    
    case "$OS" in
        alpine)
            apk update || { err "apk update 失败"; exit 1; }
            apk add --no-cache bash curl ca-certificates openssl openrc jq || {
                err "依赖安装失败"
                exit 1
            }
            
            if ! rc-service --list 2>/dev/null | grep -q "^openrc"; then
                rc-update add openrc boot >/dev/null 2>&1 || true
                rc-service openrc start >/dev/null 2>&1 || true
            fi
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y || { err "apt update 失败"; exit 1; }
            apt-get install -y curl ca-certificates openssl || {
                err "依赖安装失败"
                exit 1
            }
            ;;
        redhat)
            yum install -y curl ca-certificates openssl || {
                err "依赖安装失败"
                exit 1
            }
            ;;
        *)
            warn "未识别的系统类型，尝试继续..."
            ;;
    esac
    
    info "依赖安装完成"
}

install_deps

# -----------------------
# 配置端口和密码
get_config() {
    info "=== 配置 Shadowsocks (SS) ==="
    if [ -n "${SINGBOX_PORT_SS:-}" ]; then
        PORT_SS="$SINGBOX_PORT_SS"
        info "使用环境变量端口 (SS): $PORT_SS"
    else
        read -p "请输入 SS 端口（留空则随机 10000-60000）: " USER_PORT_SS
        if [ -z "$USER_PORT_SS" ]; then
            PORT_SS=$(shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50001 + 10000)))
            info "使用随机端口 (SS): $PORT_SS"
        else
            PORT_SS="$USER_PORT_SS"
        fi
    fi

    if [ -n "${SINGBOX_PASSWORD_SS:-}" ]; then
        PSK_SS="$SINGBOX_PASSWORD_SS"
        info "使用环境变量密码 (SS)"
    else
        read -p "请输入 SS 密码（留空则自动生成 Base64 密钥）: " USER_PSK_SS
        if [ -z "$USER_PSK_SS" ]; then
            PSK_SS=$(openssl rand -base64 16 | tr -d '\n\r' || head -c 16 /dev/urandom | base64 | tr -d '\n\r')
            info "已自动生成 SS 密码"
        else
            PSK_SS="$USER_PSK_SS"
        fi
    fi

    info "=== 配置 Hysteria2 (HY2) ==="
    if [ -n "${SINGBOX_PORT_HY2:-}" ]; then
        PORT_HY2="$SINGBOX_PORT_HY2"
        info "使用环境变量端口 (HY2): $PORT_HY2"
    else
        read -p "请输入 HY2 端口（留空则随机 10000-60000）: " USER_PORT_HY2
        if [ -z "$USER_PORT_HY2" ]; then
            PORT_HY2=$(shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50001 + 10000)))
            info "使用随机端口 (HY2): $PORT_HY2"
        else
            PORT_HY2="$USER_PORT_HY2"
        fi
    fi

    if [ -n "${SINGBOX_PASSWORD_HY2:-}" ]; then
        PSK_HY2="$SINGBOX_PASSWORD_HY2"
        info "使用环境变量密码 (HY2)"
    else
        read -p "请输入 HY2 密码（留空则自动生成 Base64 密钥）: " USER_PSK_HY2
        if [ -z "$USER_PSK_HY2" ]; then
            PSK_HY2=$(openssl rand -base64 16 | tr -d '\n\r' || head -c 16 /dev/urandom | base64 | tr -d '\n\r')
            info "已自动生成 HY2 密码"
        else
            PSK_HY2="$USER_PSK_HY2"
        fi
    fi

    info "=== 配置 VLESS Reality ==="
    if [ -n "${SINGBOX_PORT_REALITY:-}" ]; then
        PORT_REALITY="$SINGBOX_PORT_REALITY"
        info "使用环境变量端口 (Reality): $PORT_REALITY"
    else
        read -p "请输入 VLESS Reality 端口（留空则随机 10000-60000）: " USER_PORT_REALITY
        if [ -z "$USER_PORT_REALITY" ]; then
            PORT_REALITY=$(shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50001 + 10000)))
            info "使用随机端口 (Reality): $PORT_REALITY"
        else
            PORT_REALITY="$USER_PORT_REALITY"
        fi
    fi

    UUID=$(cat /proc/sys/kernel/random/uuid)
    info "已生成 UUID: $UUID"
}

get_config

# -----------------------
# 安装 sing-box
install_singbox() {
    info "开始安装 sing-box..."

    if command -v sing-box >/dev/null 2>&1; then
        CURRENT_VERSION=$(sing-box version 2>/dev/null | head -1 || echo "unknown")
        warn "检测到已安装 sing-box: $CURRENT_VERSION"
        read -p "是否重新安装？(y/N): " REINSTALL
        if [[ ! "$REINSTALL" =~ ^[Yy]$ ]]; then
            info "跳过 sing-box 安装"
            return 0
        fi
    fi

    case "$OS" in
        alpine)
            info "使用 Edge 仓库安装 sing-box"
            apk update || { err "apk update 失败"; exit 1; }
            apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community sing-box || {
                err "sing-box 安装失败"
                exit 1
            }
            ;;
        debian|redhat)
            bash <(curl -fsSL https://sing-box.app/install.sh) || {
                err "sing-box 安装失败"
                exit 1
            }
            ;;
        *)
            err "未支持的系统，无法安装 sing-box"
            exit 1
            ;;
    esac

    if ! command -v sing-box >/dev/null 2>&1; then
        err "sing-box 安装后未找到可执行文件"
        exit 1
    fi

    INSTALLED_VERSION=$(sing-box version 2>/dev/null | head -1 || echo "unknown")
    info "sing-box 安装成功: $INSTALLED_VERSION"
}

install_singbox

# -----------------------
# 生成 Reality 密钥对和自签名证书
generate_reality_keys() {
    info "生成 Reality 密钥对..."
    REALITY_KEYS=$(sing-box generate reality-keypair)
    REALITY_PK=$(echo "$REALITY_KEYS" | grep "PrivateKey" | awk '{print $NF}')
    REALITY_PUB=$(echo "$REALITY_KEYS" | grep "PublicKey" | awk '{print $NF}')
    REALITY_SID=$(sing-box generate rand 8 --hex)
    
    info "Reality PK: $REALITY_PK"
    info "Reality PUB: $REALITY_PUB"
    info "Reality SID: $REALITY_SID"
}

generate_reality_keys

# -----------------------
# 生成 HY2 自签名证书
generate_hy2_cert() {
    info "生成 HY2 自签名证书..."
    mkdir -p /etc/sing-box/certs
    
    if [ ! -f /etc/sing-box/certs/fullchain.pem ] || [ ! -f /etc/sing-box/certs/privkey.pem ]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
          -keyout /etc/sing-box/certs/privkey.pem \
          -out /etc/sing-box/certs/fullchain.pem \
          -days 3650 \
          -subj "/CN=www.bing.com" || {
            err "证书生成失败"
            exit 1
        }
        info "HY2 证书已生成"
    else
        info "HY2 证书已存在"
    fi
}

generate_hy2_cert

# -----------------------
# 生成配置文件
CONFIG_PATH="/etc/sing-box/config.json"

create_config() {
    info "生成配置文件: $CONFIG_PATH"
    
    mkdir -p "$(dirname "$CONFIG_PATH")"
    
    cat > "$CONFIG_PATH" <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "shadowsocks",
      "listen": "::",
      "listen_port": $PORT_SS,
      "method": "2022-blake3-aes-128-gcm",
      "password": "$PSK_SS",
      "tag": "ss-in"
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": $PORT_HY2,
      "users": [
        {
          "password": "$PSK_HY2"
        }
      ],
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"
      }
    },
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $PORT_REALITY,
      "users": [
        {
          "uuid": "$UUID",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "addons.mozilla.org",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "addons.mozilla.org",
            "server_port": 443
          },
          "private_key": "$REALITY_PK",
          "short_id": ["$REALITY_SID"]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct-out"
    }
  ]
}
EOF

    if command -v sing-box >/dev/null 2>&1; then
        if sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1; then
            info "配置文件验证通过"
        else
            warn "配置文件验证失败，但将继续..."
        fi
    fi
    
    # 保存所有配置到独立文件供 sb 脚本读取
    mkdir -p /etc/sing-box
    cat > /etc/sing-box/.config_cache <<CACHE
SS_PORT=$PORT_SS
SS_PSK=$PSK_SS
SS_METHOD=2022-blake3-aes-128-gcm
HY2_PORT=$PORT_HY2
HY2_PSK=$PSK_HY2
REALITY_PORT=$PORT_REALITY
REALITY_UUID=$UUID
REALITY_PK=$REALITY_PK
REALITY_SID=$REALITY_SID
REALITY_PUB=$REALITY_PUB
CACHE
    
    info "配置缓存已保存到 /etc/sing-box/.config_cache"
}

create_config

# -----------------------
# 设置服务
setup_service() {
    info "配置系统服务..."
    
    if [ "$OS" = "alpine" ]; then
        SERVICE_PATH="/etc/init.d/sing-box"
        
        cat > "$SERVICE_PATH" <<'OPENRC'
#!/sbin/openrc-run

name="sing-box"
description="Sing-box Proxy Server"
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
pidfile="/run/${RC_SVCNAME}.pid"
command_background="yes"
output_log="/var/log/sing-box.log"
error_log="/var/log/sing-box.err"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --mode 0755 /var/log
    checkpath --directory --mode 0755 /run
}
OPENRC
        
        chmod +x "$SERVICE_PATH"
        rc-update add sing-box default >/dev/null 2>&1 || warn "添加开机自启失败"
        rc-service sing-box restart || {
            err "服务启动失败"
            tail -20 /var/log/sing-box.err 2>/dev/null || tail -20 /var/log/sing-box.log 2>/dev/null || true
            exit 1
        }
        
        sleep 2
        if rc-service sing-box status >/dev/null 2>&1; then
            info "✅ OpenRC 服务已启动"
        else
            err "服务状态异常"
            exit 1
        fi
        
    else
        SERVICE_PATH="/etc/systemd/system/sing-box.service"
        
        cat > "$SERVICE_PATH" <<'SYSTEMD'
[Unit]
Description=Sing-box Proxy Server
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SYSTEMD
        
        systemctl daemon-reload
        systemctl enable sing-box >/dev/null 2>&1
        systemctl restart sing-box || {
            err "服务启动失败"
            journalctl -u sing-box -n 30 --no-pager
            exit 1
        }
        
        sleep 2
        if systemctl is-active sing-box >/dev/null 2>&1; then
            info "✅ Systemd 服务已启动"
        else
            err "服务状态异常"
            exit 1
        fi
    fi
    
    info "服务配置完成: $SERVICE_PATH"
}

setup_service

# -----------------------
# 获取公网 IP
get_public_ip() {
    local ip=""
    for url in \
        "https://api.ipify.org" \
        "https://ipinfo.io/ip" \
        "https://ifconfig.me" \
        "https://icanhazip.com" \
        "https://ipecho.net/plain"; do
        ip=$(curl -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

PUB_IP=$(get_public_ip || echo "YOUR_SERVER_IP")
if [ "$PUB_IP" = "YOUR_SERVER_IP" ]; then
    warn "无法获取公网 IP，请手动替换"
else
    info "检测到公网 IP: $PUB_IP"
fi

# -----------------------
# 生成链接
generate_uris() {
    local host="$PUB_IP"
    
    # SS URI
    local ss_userinfo="2022-blake3-aes-128-gcm:${PSK_SS}"
    if command -v python3 >/dev/null 2>&1; then
        ss_encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$ss_userinfo" 2>/dev/null || echo "$ss_userinfo")
    else
        ss_encoded=$(printf "%s" "$ss_userinfo" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
    fi
    ss_b64=$(printf "%s" "$ss_userinfo" | base64 -w0 2>/dev/null || printf "%s" "$ss_userinfo" | base64 | tr -d '\n')
    
    echo "=== Shadowsocks (SS) ==="
    echo "ss://${ss_encoded}@${host}:${PORT_SS}#singbox-ss"
    echo "ss://${ss_b64}@${host}:${PORT_SS}#singbox-ss"
    echo ""
    
    # HY2 URI
    echo "=== Hysteria2 (HY2) ==="
    echo "hy2://${PSK_HY2}@${host}:${PORT_HY2}/?sni=www.bing.com#singbox-hy2"
    echo ""
    
    # VLESS Reality URI
    echo "=== VLESS Reality ==="
    echo "vless://${UUID}@${host}:${PORT_REALITY}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=addons.mozilla.org&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}#singbox-reality"
}

# -----------------------
# 最终输出
echo ""
echo "=========================================="
info "🎉 Sing-box 多协议部署完成！"
echo "=========================================="
echo ""
info "📋 配置信息："
echo "   SS 端口: $PORT_SS | 密码: $PSK_SS"
echo "   HY2 端口: $PORT_HY2 | 密码: $PSK_HY2"
echo "   Reality 端口: $PORT_REALITY | UUID: $UUID"
echo "   服务器: $PUB_IP"
echo ""
info "📂 文件位置："
echo "   配置: $CONFIG_PATH"
echo "   证书: /etc/sing-box/certs/"
echo "   服务: $SERVICE_PATH"
echo ""
info "🔗 客户端链接："
generate_uris | while IFS= read -r line; do
    echo "   $line"
done
echo ""
info "📧 管理命令："
if [ "$OS" = "alpine" ]; then
    echo "   启动: rc-service sing-box start"
    echo "   停止: rc-service sing-box stop"
    echo "   重启: rc-service sing-box restart"
    echo "   状态: rc-service sing-box status"
    echo "   日志: tail -f /var/log/sing-box.log"
else
    echo "   启动: systemctl start sing-box"
    echo "   停止: systemctl stop sing-box"
    echo "   重启: systemctl restart sing-box"
    echo "   状态: systemctl status sing-box"
    echo "   日志: journalctl -u sing-box -f"
fi
echo ""
echo "=========================================="

# -----------------------
# Create `sb` management script at /usr/local/bin/sb

SB_PATH="/usr/local/bin/sb"

info "正在创建 sb 管理脚本: $SB_PATH"

cat > "$SB_PATH" <<'SB_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

# -----------------------
# 颜色输出函数
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

CONFIG_PATH="/etc/sing-box/config.json"
URI_PATH="/etc/sing-box/uris.txt"
REALITY_PUB_FILE="/etc/sing-box/.reality_pub"
BIN_PATH="/usr/bin/sing-box"
SERVICE_NAME="sing-box"

# detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        ID="${ID:-}"
        ID_LIKE="${ID_LIKE:-}"
    else
        ID=""
        ID_LIKE=""
    fi

    if echo "$ID $ID_LIKE" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "$ID $ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "$ID $ID_LIKE" | grep -Ei "centos|rhel|fedora" >/dev/null; then
        OS="redhat"
    else
        OS="unknown"
    fi
}

detect_os

# service helpers
service_start() {
    if [ "$OS" = "alpine" ]; then
        rc-service "$SERVICE_NAME" start
    else
        systemctl start "$SERVICE_NAME"
    fi
}
service_stop() {
    if [ "$OS" = "alpine" ]; then
        rc-service "$SERVICE_NAME" stop
    else
        systemctl stop "$SERVICE_NAME"
    fi
}
service_restart() {
    if [ "$OS" = "alpine" ]; then
        rc-service "$SERVICE_NAME" restart
    else
        systemctl restart "$SERVICE_NAME"
    fi
}
service_status() {
    if [ "$OS" = "alpine" ]; then
        rc-service "$SERVICE_NAME" status
    else
        systemctl status "$SERVICE_NAME" --no-pager
    fi
}

# Extract all three protocols from config.json
read_config_fields() {
    if [ ! -f "$CONFIG_PATH" ]; then
        err "未找到配置文件: $CONFIG_PATH"
        return 1
    fi

    # 优先从缓存文件读取（最可靠）
    if [ -f /etc/sing-box/.config_cache ]; then
        source /etc/sing-box/.config_cache
        return 0
    fi

    # 备选：使用 jq 解析 JSON
    if command -v jq >/dev/null 2>&1; then
        SS_PORT=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .listen_port' "$CONFIG_PATH" 2>/dev/null | head -1)
        SS_PSK=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .password' "$CONFIG_PATH" 2>/dev/null | head -1)
        SS_METHOD=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .method' "$CONFIG_PATH" 2>/dev/null | head -1)
        
        HY2_PORT=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .listen_port' "$CONFIG_PATH" 2>/dev/null | head -1)
        HY2_PSK=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password' "$CONFIG_PATH" 2>/dev/null | head -1)
        
        REALITY_PORT=$(jq -r '.inbounds[] | select(.type=="vless") | .listen_port' "$CONFIG_PATH" 2>/dev/null | head -1)
        REALITY_UUID=$(jq -r '.inbounds[] | select(.type=="vless") | .users[0].uuid' "$CONFIG_PATH" 2>/dev/null | head -1)
        REALITY_PK=$(jq -r '.inbounds[] | select(.type=="vless") | .tls.reality.private_key' "$CONFIG_PATH" 2>/dev/null | head -1)
        REALITY_SID=$(jq -r '.inbounds[] | select(.type=="vless") | .tls.reality.short_id[0]' "$CONFIG_PATH" 2>/dev/null | head -1)
    fi

    # 从保存的文件读取 Reality 相关信息
    if [ -f /etc/sing-box/.reality_pub ]; then
        REALITY_PUB=$(cat /etc/sing-box/.reality_pub)
    fi
    
    # 设置默认值
    SS_PORT="${SS_PORT:-}"
    SS_PSK="${SS_PSK:-}"
    SS_METHOD="${SS_METHOD:-2022-blake3-aes-128-gcm}"
    HY2_PORT="${HY2_PORT:-}"
    HY2_PSK="${HY2_PSK:-}"
    REALITY_PORT="${REALITY_PORT:-}"
    REALITY_UUID="${REALITY_UUID:-}"
    REALITY_PK="${REALITY_PK:-}"
    REALITY_SID="${REALITY_SID:-}"
    REALITY_PUB="${REALITY_PUB:-}"
}

# generate uris from current config and save
generate_and_save_uris() {
    read_config_fields || return 1

    PUBLIC_IP=""
    for url in "https://api.ipify.org" "https://ipinfo.io/ip" "https://ifconfig.me" "https://icanhazip.com" "https://ipecho.net/plain"; do
        PUBLIC_IP=$(curl -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        if [ -n "$PUBLIC_IP" ]; then break; fi
    done
    if [ -z "$PUBLIC_IP" ]; then PUBLIC_IP="YOUR_SERVER_IP"; fi

    # SS URI
    ss_userinfo="${SS_METHOD}:${SS_PSK}"
    if command -v python3 >/dev/null 2>&1; then
        ss_encoded=$(python3 - <<PY
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
"$ss_userinfo")
    else
        ss_encoded=$(printf "%s" "$ss_userinfo" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
    fi
    ss_b64=$(printf "%s" "$ss_userinfo" | base64 -w0 2>/dev/null || printf "%s" "$ss_userinfo" | base64 | tr -d '\n')

    # HY2 URI
    hy2_uri="hy2://${HY2_PSK}@${PUBLIC_IP}:${HY2_PORT}/?sni=www.bing.com#singbox-hy2"

    # Read pub key from stored file
    if [ -f "$REALITY_PUB_FILE" ]; then
        REALITY_PUB=$(cat "$REALITY_PUB_FILE")
    else
        REALITY_PUB="UNKNOWN"
    fi
    
    # Read SID from stored file or config
    if [ -z "$REALITY_SID" ]; then
        if [ -f "/etc/sing-box/.reality_sid" ]; then
            REALITY_SID=$(cat /etc/sing-box/.reality_sid)
        else
            REALITY_SID="UNKNOWN"
        fi
    fi

    reality_uri="vless://${REALITY_UUID}@${PUBLIC_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=addons.mozilla.org&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}#singbox-reality"

    {
        echo "=== Shadowsocks (SS) ==="
        echo "ss://${ss_encoded}@${PUBLIC_IP}:${SS_PORT}#singbox-ss"
        echo "ss://${ss_b64}@${PUBLIC_IP}:${SS_PORT}#singbox-ss"
        echo ""
        echo "=== Hysteria2 (HY2) ==="
        echo "$hy2_uri"
        echo ""
        echo "=== VLESS Reality ==="
        echo "$reality_uri"
    } > "$URI_PATH"

    info "URI 已写入: $URI_PATH"
}

# View all URIs
action_view_uri() {
    info "正在从配置生成 URI..."
    generate_and_save_uris || { err "生成 URI 失败"; return 1; }
    echo ""
    cat "$URI_PATH"
}

# View config path
action_view_config() {
    echo "$CONFIG_PATH"
}

# Edit config
action_edit_config() {
    if [ ! -f "$CONFIG_PATH" ]; then
        err "配置文件不存在: $CONFIG_PATH"
        return 1
    fi

    if command -v nano >/dev/null 2>&1; then
        ${EDITOR:-nano} "$CONFIG_PATH"
    else
        ${EDITOR:-vi} "$CONFIG_PATH"
    fi

    if command -v sing-box >/dev/null 2>&1; then
        if sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1; then
            info "配置校验通过，重启服务"
            service_restart || warn "重启失败"
            generate_and_save_uris || true
        else
            warn "配置校验失败，请手动检查。服务未被重启。"
        fi
    else
        warn "未检测到 sing-box 可执行文件，无法校验或重启"
    fi
}

# Reset SS port & password
action_reset_ss() {
    [ -f "$CONFIG_PATH" ] || { err "配置文件不存在: $CONFIG_PATH"; return 1; }
    read_config_fields || return 1

    read -p "输入新的 SS 端口（回车保持 $SS_PORT）: " new_ss_port
    [ -z "$new_ss_port" ] && new_ss_port="$SS_PORT"

    read -p "输入新的 SS 密码（回车随机生成）: " new_ss_psk
    [ -z "$new_ss_psk" ] && new_ss_psk=$(openssl rand -base64 16 | tr -d '\n\r')

    info "正在停止服务..."
    service_stop || warn "停止服务失败"

    # Update SS inbound only
    python3 - <<PY
import json
with open('$CONFIG_PATH') as f:
    c=json.load(f)
for ib in c.get('inbounds',[]):
    if ib.get('type')=='shadowsocks':
        ib['listen_port']=$new_ss_port
        ib['password']='$new_ss_psk'
        break
with open('$CONFIG_PATH','w') as f:
    json.dump(c,f,indent=2)
PY

    # 更新缓存
    sed -i "s/^SS_PORT=.*/SS_PORT=$new_ss_port/" /etc/sing-box/.config_cache
    sed -i "s/^SS_PSK=.*/SS_PSK=$new_ss_psk/" /etc/sing-box/.config_cache

    info "已更新 SS 端口($new_ss_port)与密码(隐藏)，正在启动服务..."
    service_start || warn "启动服务失败"
    sleep 1
    generate_and_save_uris || warn "生成 URI 失败"
}

# Reset HY2 port & password
action_reset_hy2() {
    [ -f "$CONFIG_PATH" ] || { err "配置文件不存在: $CONFIG_PATH"; return 1; }
    read_config_fields || return 1

    read -p "输入新的 HY2 端口（回车保持 $HY2_PORT）: " new_hy2_port
    [ -z "$new_hy2_port" ] && new_hy2_port="$HY2_PORT"

    read -p "输入新的 HY2 密码（回车随机生成）: " new_hy2_psk
    [ -z "$new_hy2_psk" ] && new_hy2_psk=$(openssl rand -base64 16 | tr -d '\n\r')

    info "正在停止服务..."
    service_stop || warn "停止服务失败"

    python3 - <<PY
import json
with open('$CONFIG_PATH') as f:
    c=json.load(f)
for ib in c.get('inbounds',[]):
    if ib.get('type')=='hysteria2':
        ib['listen_port']=$new_hy2_port
        users=ib.get('users',[])
        if users:
            users[0]['password']='$new_hy2_psk'
        break
with open('$CONFIG_PATH','w') as f:
    json.dump(c,f,indent=2)
PY

    # 更新缓存
    sed -i "s/^HY2_PORT=.*/HY2_PORT=$new_hy2_port/" /etc/sing-box/.config_cache
    sed -i "s/^HY2_PSK=.*/HY2_PSK=$new_hy2_psk/" /etc/sing-box/.config_cache

    info "已更新 HY2 端口($new_hy2_port)与密码(隐藏)，正在启动服务..."
    service_start || warn "启动服务失败"
    sleep 1
    generate_and_save_uris || warn "生成 URI 失败"
}

# Reset Reality port & UUID
action_reset_reality() {
    [ -f "$CONFIG_PATH" ] || { err "配置文件不存在: $CONFIG_PATH"; return 1; }
    read_config_fields || return 1

    read -p "输入新的 Reality 端口（回车保持 $REALITY_PORT）: " new_reality_port
    [ -z "$new_reality_port" ] && new_reality_port="$REALITY_PORT"

    read -p "输入新的 Reality UUID（回车随机生成）: " new_reality_uuid
    if [ -z "$new_reality_uuid" ]; then
        new_reality_uuid=$(cat /proc/sys/kernel/random/uuid)
    fi

    info "正在停止服务..."
    service_stop || warn "停止服务失败"

    python3 - <<PY
import json
with open('$CONFIG_PATH') as f:
    c=json.load(f)
for ib in c.get('inbounds',[]):
    if ib.get('type')=='vless':
        ib['listen_port']=$new_reality_port
        users=ib.get('users',[])
        if users:
            users[0]['uuid']='$new_reality_uuid'
        break
with open('$CONFIG_PATH','w') as f:
    json.dump(c,f,indent=2)
PY

    info "已更新 Reality 端口($new_reality_port)与 UUID(隐藏)，正在启动服务..."
    service_start || warn "启动服务失败"
    sleep 1
    generate_and_save_uris || warn "生成 URI 失败"
}

# Update sing-box
action_update() {
    info "开始更新 sing-box..."
    if [ "$OS" = "alpine" ]; then
        apk update || warn "apk update 失败"
        apk add --upgrade --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community sing-box || {
            warn "apk 更新失败，尝试用官方安装脚本"
            bash <(curl -fsSL https://sing-box.app/install.sh) || err "更新失败"
        }
    else
        bash <(curl -fsSL https://sing-box.app/install.sh) || err "更新失败"
    fi

    info "更新完成，重启服务..."
    if command -v sing-box >/dev/null 2>&1; then
        NEW_VER=$(sing-box version 2>/dev/null | head -1 || echo "unknown")
        info "当前 sing-box 版本: $NEW_VER"
        service_restart || warn "重启失败"
    else
        warn "更新后未检测到 sing-box 可执行文件"
    fi
}

# Uninstall sing-box
action_uninstall() {
    info "正在卸载 sing-box..."
    service_stop || true
    if [ "$OS" = "alpine" ]; then
        rc-update del "$SERVICE_NAME" default >/dev/null 2>&1 || true
        [ -f "/etc/init.d/$SERVICE_NAME" ] && rm -f "/etc/init.d/$SERVICE_NAME"
        apk del sing-box >/dev/null 2>&1 || true
    else
        systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
        [ -f "/etc/systemd/system/$SERVICE_NAME.service" ] && rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    rm -rf /etc/sing-box /var/log/sing-box* /usr/local/bin/sb "$BIN_PATH" >/dev/null 2>&1 || true
    info "卸载完成"
}

# Generate relay script (SS only - unchanged)
action_generate_relay_script() {
    info "准备生成线路鸡一键安装脚本..."
    read_config_fields || return 1

    PUBLIC_IP=""
    for url in \
        "https://api.ipify.org" \
        "https://ipinfo.io/ip" \
        "https://ifconfig.me" \
        "https://icanhazip.com" \
        "https://ipecho.net/plain"; do
        
        PUBLIC_IP=$(curl -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')
        if [ -n "$PUBLIC_IP" ]; then break; fi
    done
    [ -z "$PUBLIC_IP" ] && PUBLIC_IP="YOUR_SERVER_IP"

    info "落地机出口节点：${PUBLIC_IP}:${SS_PORT}  方法:${SS_METHOD}"

    RELAY_SCRIPT_PATH="/tmp/relay-install.sh"

    cat > "$RELAY_SCRIPT_PATH" << 'RELAY_TEMPLATE'
#!/usr/bin/env bash
set -euo pipefail
INBOUND_IP="__INBOUND_IP__"
INBOUND_PORT="__INBOUND_PORT__"
INBOUND_METHOD="__INBOUND_METHOD__"
INBOUND_PASSWORD="__INBOUND_PASSWORD__"
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
if [ "$(id -u)" != "0" ]; then
    err "必须以 root 运行"
    exit 1
fi
detect_os() {
    . /etc/os-release 2>/dev/null || true
    case "$ID" in
        alpine) OS=alpine ;;
        debian|ubuntu) OS=debian ;;
        centos|rhel|fedora) OS=redhat ;;
        *) OS=unknown ;;
    esac
}
detect_os
info "检测到系统: $OS"
install_deps() {
    info "安装依赖..."
    case "$OS" in
        alpine)
            apk update
            apk add --no-cache curl jq bash openssl ca-certificates
        ;;
        debian)
            apt-get update -y
            apt-get install -y curl jq bash openssl ca-certificates
        ;;
        redhat)
            yum install -y curl jq bash openssl ca-certificates
        ;;
    esac
}
install_deps
install_singbox() {
    info "安装 sing-box..."
    case "$OS" in
        alpine)
            apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community sing-box
        ;;
        *)
            bash <(curl -fsSL https://sing-box.app/install.sh)
        ;;
    esac
}
install_singbox
UUID=$(cat /proc/sys/kernel/random/uuid)
info "生成 Reality 密钥对"
REALITY_KEYS=$(sing-box generate reality-keypair)
REALITY_PK=$(echo "$REALITY_KEYS" | grep "PrivateKey" | awk '{print $NF}')
REALITY_PUB=$(echo "$REALITY_KEYS" | grep "PublicKey" | awk '{print $NF}')
info "Reality PK: $REALITY_PK"
info "Reality PUB: $REALITY_PUB"
REALITY_SID=$(sing-box generate rand 8 --hex)
info "Reality SID: $REALITY_SID"
read -p "输入线路鸡监听端口（留空则随机 20000-65000）: " USER_PORT
if [ -z "$USER_PORT" ]; then
    LISTEN_PORT=$(shuf -i 20000-65000 -n 1 2>/dev/null || echo $((RANDOM % 45001 + 20000)))
    info "使用随机端口: $LISTEN_PORT"
else
    if ! [[ "$USER_PORT" =~ ^[0-9]+$ ]] || [ "$USER_PORT" -lt 1 ] || [ "$USER_PORT" -gt 65535 ]; then
        err "端口必须为 1-65535 的数字"
        exit 1
    fi
    LISTEN_PORT="$USER_PORT"
fi
info "线路鸡监听端口: $LISTEN_PORT"
mkdir -p /etc/sing-box
cat > /etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "listen": "::",
      "listen_port": $LISTEN_PORT,
      "sniff": true,
      "users": [
        {
          "uuid": "$UUID",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "addons.mozilla.org",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "addons.mozilla.org",
            "server_port": 443
          },
          "private_key": "$REALITY_PK",
          "short_id": [
            "$REALITY_SID"
          ],
          "max_time_difference": "1m"
        }
      },
      "tag": "vless-in"
    }
  ],
  "outbounds": [
    {
      "type": "shadowsocks",
      "server": "$INBOUND_IP",
      "server_port": $INBOUND_PORT,
      "method": "$INBOUND_METHOD",
      "password": "$INBOUND_PASSWORD",
      "tag": "relay-out"
    },
    {
      "type": "direct",
      "tag": "direct-out"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": "vless-in",
        "outbound": "relay-out"
      }
    ]
  }
}
EOF
if [ "$OS" = "alpine" ]; then
    cat > /etc/init.d/sing-box << 'SVC'
#!/sbin/openrc-run
name="sing-box"
description="SingBox service"
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/sing-box.pid"
depend() {
    need net
}
SVC
    chmod +x /etc/init.d/sing-box
    rc-update add sing-box default
    rc-service sing-box restart
else
    cat > /etc/systemd/system/sing-box.service << 'SYSTEMD'
[Unit]
Description=Sing-box Relay
After=network.target
[Service]
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
SYSTEMD
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl restart sing-box
fi
PUB_IP=$(curl -s https://api.ipify.org || echo "YOUR_RELAY_IP")
echo ""
echo "✅ 安装完成"
echo "VLESS Reality 中转节点："
echo "vless://$UUID@$PUB_IP:$LISTEN_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=addons.mozilla.org&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID#relay"
echo ""
RELAY_TEMPLATE

    sed -i "s|__INBOUND_IP__|$PUBLIC_IP|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_PORT__|$SS_PORT|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_METHOD__|$SS_METHOD|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_PASSWORD__|$SS_PSK|g" "$RELAY_SCRIPT_PATH"

    chmod +x "$RELAY_SCRIPT_PATH"

    echo ""
    info "✅ 线路鸡脚本已生成：$RELAY_SCRIPT_PATH"
    echo ""
    info "请手动复制以下内容到线路鸡，保存为 /tmp/relay-install.sh，并执行"
    echo "------------------------------------------"
    cat "$RELAY_SCRIPT_PATH"
    echo "------------------------------------------"
    echo ""
    info "在线路鸡执行："
    echo "   chmod +x /tmp/relay-install.sh && bash /tmp/relay-install.sh"
}

# -----------------------
# Main Menu
while true; do
    cat <<'MENU'

==========================
 Sing-box 管理面板 (sb)
==========================
1) 查看三协议链接 (SS/HY2/Reality)
2) 查看配置文件路径
3) 编辑配置文件
4) 重置 SS 端口/密码
5) 重置 HY2 端口/密码
6) 重置 Reality 端口/UUID
7) 启动服务
8) 停止服务
9) 重启服务
10) 查看状态
11) 更新 sing-box
12) 生成线路鸡脚本 (SS 出站)
13) 卸载 sing-box
0) 退出
==========================
MENU

    read -p "请输入选项: " opt
    case "${opt:-}" in
        1) action_view_uri ;;
        2) action_view_config ;;
        3) action_edit_config ;;
        4) action_reset_ss ;;
        5) action_reset_hy2 ;;
        6) action_reset_reality ;;
        7) service_start && info "已发送启动命令" ;;
        8) service_stop && info "已发送停止命令" ;;
        9) service_restart && info "已发送重启命令" ;;
        10) service_status ;;
        11) action_update ;;
        12) action_generate_relay_script ;;
        13) action_uninstall; exit 0 ;;
        0) exit 0 ;;
        *) warn "无效选项" ;;
    esac

    echo ""
done
SB_SCRIPT

chmod +x "$SB_PATH" || warn "无法设置 $SB_PATH 为可执行"

info "sb 已创建：请输入 sb 运行管理面板"

# end of script
