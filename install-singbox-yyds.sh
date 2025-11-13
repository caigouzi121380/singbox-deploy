#!/usr/bin/env bash
set -euo pipefail

# -----------------------
# 彩色输出函数
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
        err "此脚本需要 root 权限"
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
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y || { err "apt update 失败"; exit 1; }
            apt-get install -y curl ca-certificates openssl jq || {
                err "依赖安装失败"
                exit 1
            }
            ;;
        redhat)
            yum install -y curl ca-certificates openssl jq || {
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
# 配置节点名后缀
echo "请输入节点名称（留空则默认协议名）："
read -r user_name
if [[ -n "$user_name" ]]; then
    suffix="-${user_name}"
    echo "$suffix" > /root/node_names.txt
else
    suffix=""
fi

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

    info "=== 配置 TUIC ==="
    if [ -n "${SINGBOX_PORT_TUIC:-}" ]; then
        PORT_TUIC="$SINGBOX_PORT_TUIC"
        info "使用环境变量端口 (TUIC): $PORT_TUIC"
    else
        read -p "请输入 TUIC 端口（留空则随机 10000-60000）: " USER_PORT_TUIC
        if [ -z "$USER_PORT_TUIC" ]; then
            PORT_TUIC=$(shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50001 + 10000)))
            info "使用随机端口 (TUIC): $PORT_TUIC"
        else
            PORT_TUIC="$USER_PORT_TUIC"
        fi
    fi

    if [ -n "${SINGBOX_PASSWORD_TUIC:-}" ]; then
        PSK_TUIC="$SINGBOX_PASSWORD_TUIC"
        info "使用环境变量密码 (TUIC)"
    else
        read -p "请输入 TUIC 密码（留空则自动生成 Base64 密钥）: " USER_PSK_TUIC
        if [ -z "$USER_PSK_TUIC" ]; then
            PSK_TUIC=$(openssl rand -base64 16 | tr -d '\n\r' || head -c 16 /dev/urandom | base64 | tr -d '\n\r')
            info "已自动生成 TUIC 密码"
        else
            PSK_TUIC="$USER_PSK_TUIC"
        fi
    fi

    if [ -n "${SINGBOX_UUID_TUIC:-}" ]; then
        UUID_TUIC="$SINGBOX_UUID_TUIC"
        info "使用环境变量 UUID (TUIC)"
    else
        read -p "请输入 TUIC UUID（留空则自动生成）: " USER_UUID_TUIC
        if [ -z "$USER_UUID_TUIC" ]; then
            UUID_TUIC=$(cat /proc/sys/kernel/random/uuid)
            info "已自动生成 TUIC UUID"
        else
            UUID_TUIC="$USER_UUID_TUIC"
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
    REALITY_PK=$(echo "$REALITY_KEYS" | grep "PrivateKey" | awk '{print $NF}' | tr -d '\r')
    REALITY_PUB=$(echo "$REALITY_KEYS" | grep "PublicKey" | awk '{print $NF}' | tr -d '\r')
    REALITY_SID=$(sing-box generate rand 8 --hex)
    
    mkdir -p /etc/sing-box
    echo -n "$REALITY_PUB" > /etc/sing-box/.reality_pub
    echo -n "$REALITY_SID" > /etc/sing-box/.reality_sid
    
    info "Reality PK: $REALITY_PK"
    info "Reality PUB: $REALITY_PUB"
    info "Reality SID: $REALITY_SID"
}

generate_reality_keys

# -----------------------
# 生成 HY2/TUIC 自签名证书（共用）
generate_cert() {
    info "生成 HY2/TUIC 自签名证书..."
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
        info "证书已生成"
    else
        info "证书已存在"
    fi
}

generate_cert

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
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": $PORT_TUIC,
      "users": [
        {
          "uuid": "$UUID_TUIC",
          "password": "$PSK_TUIC"
        }
      ],
      "congestion_control": "bbr",
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

    sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1 \
       && info "配置文件验证通过" \
       || warn "配置文件验证失败，但继续执行"

    mkdir -p /etc/sing-box
    cat > /etc/sing-box/.config_cache <<CACHEEOF
SS_PORT=$PORT_SS
SS_PSK=$PSK_SS
SS_METHOD=2022-blake3-aes-128-gcm
HY2_PORT=$PORT_HY2
HY2_PSK=$PSK_HY2
TUIC_PORT=$PORT_TUIC
TUIC_UUID=$UUID_TUIC
TUIC_PSK=$PSK_TUIC
REALITY_PORT=$PORT_REALITY
REALITY_UUID=$UUID
REALITY_PK=$REALITY_PK
REALITY_SID=$REALITY_SID
REALITY_PUB=$REALITY_PUB
CACHEEOF

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
    ss_encoded=$(printf "%s" "$ss_userinfo" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
    ss_b64=$(printf "%s" "$ss_userinfo" | base64 -w0 2>/dev/null || printf "%s" "$ss_userinfo" | base64 | tr -d '\n')

    # HY2 URI
    hy2_encoded=$(printf "%s" "$PSK_HY2" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')

    # TUIC URI
    tuic_encoded=$(printf "%s" "$PSK_TUIC" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')

    echo "=== Shadowsocks (SS) ==="
    echo "ss://${ss_encoded}@${host}:${PORT_SS}#ss${suffix}"
    echo "ss://${ss_b64}@${host}:${PORT_SS}#ss${suffix}"
    echo ""
    
    echo "=== Hysteria2 (HY2) ==="
    echo "hy2://${hy2_encoded}@${host}:${PORT_HY2}/?sni=www.bing.com&alpn=h3&insecure=1#hy2${suffix}"
    echo ""

    echo "=== TUIC ==="
    echo "tuic://${UUID_TUIC}:${tuic_encoded}@${host}:${PORT_TUIC}/?congestion_control=bbr&alpn=h3&sni=www.bing.com&insecure=1#tuic${suffix}"
    echo ""
    
    echo "=== VLESS Reality ==="
    echo "vless://${UUID}@${host}:${PORT_REALITY}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=addons.mozilla.org&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}#reality${suffix}"
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
echo "   TUIC 端口: $PORT_TUIC | UUID: $UUID_TUIC | 密码: $PSK_TUIC"
echo "   Reality 端口: $PORT_REALITY | UUID: $UUID"
echo "   服务器: $PUB_IP"
echo ""
info "📂 文件位置："
echo "   配置: $CONFIG_PATH"
echo "   证书: /etc/sing-box/certs/"
echo "   服务: $SERVICE_PATH"
echo ""
info "📜 客户端链接："
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
# sb 管理面板（无 python3，使用 jq）
# 兼容: alpine / debian / redhat
# 依赖: jq, curl, openssl 或 /dev/urandom
# -----------------------

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

CONFIG_PATH="${CONFIG_PATH:-/etc/sing-box/config.json}"
URI_PATH="${URI_PATH:-/etc/sing-box/uris.txt}"
REALITY_PUB_FILE="${REALITY_PUB_FILE:-/etc/sing-box/.reality_pub}"
SERVICE_NAME="${SERVICE_NAME:-sing-box}"
BIN_PATH="${BIN_PATH:-/usr/bin/sing-box}"

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
        rc-service "$SERVICE_NAME" start || return $?
    else
        systemctl start "$SERVICE_NAME" || return $?
    fi
}
service_stop() {
    if [ "$OS" = "alpine" ]; then
        rc-service "$SERVICE_NAME" stop || return $?
    else
        systemctl stop "$SERVICE_NAME" || return $?
    fi
}
service_restart() {
    if [ "$OS" = "alpine" ]; then
        rc-service "$SERVICE_NAME" restart || return $?
    else
        systemctl restart "$SERVICE_NAME" || return $?
    fi
}
service_status() {
    if [ "$OS" = "alpine" ]; then
        rc-service "$SERVICE_NAME" status || return $?
    else
        systemctl status "$SERVICE_NAME" --no-pager || return $?
    fi
}

# Safe random
rand_b64() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 16 | tr -d '\n\r'
    else
        head -c 16 /dev/urandom | base64 | tr -d '\n\r'
    fi
}

# Generate UUID
rand_uuid() {
    if [ -f /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    else
        openssl rand -hex 16 | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1\2\3\4-\5\6-\7\8-\9\10-\11\12\13\14\15\16/'
    fi
}

# URL-encode minimal (for userinfo like "method:password")
url_encode_min() {
    local s="$1"
    printf "%s" "$s" | sed -e 's/%/%25/g' \
                             -e 's/:/%3A/g' \
                             -e 's/+/%2B/g' \
                             -e 's/\//%2F/g' \
                             -e 's/=/\%3D/g'
}

# read JSON fields from config using jq
read_config_fields() {
    if [ ! -f "$CONFIG_PATH" ]; then
        err "未找到配置文件: $CONFIG_PATH"
        return 1
    fi

    # Shadowsocks
    SS_PORT=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .listen_port // empty' "$CONFIG_PATH" | head -n1 || true)
    SS_PSK=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .password // empty' "$CONFIG_PATH" | head -n1 || true)
    SS_METHOD=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .method // empty' "$CONFIG_PATH" | head -n1 || true)

    # Hysteria2
    HY2_PORT=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .listen_port // empty' "$CONFIG_PATH" | head -n1 || true)
    HY2_PSK=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password // empty' "$CONFIG_PATH" | head -n1 || true)

    # TUIC
    TUIC_PORT=$(jq -r '.inbounds[] | select(.type=="tuic") | .listen_port // empty' "$CONFIG_PATH" | head -n1 || true)
    TUIC_UUID=$(jq -r '.inbounds[] | select(.type=="tuic") | .users[0].uuid // empty' "$CONFIG_PATH" | head -n1 || true)
    TUIC_PSK=$(jq -r '.inbounds[] | select(.type=="tuic") | .users[0].password // empty' "$CONFIG_PATH" | head -n1 || true)

    # VLESS / Reality
    REALITY_PORT=$(jq -r '.inbounds[] | select(.type=="vless") | .listen_port // empty' "$CONFIG_PATH" | head -n1 || true)
    REALITY_UUID=$(jq -r '.inbounds[] | select(.type=="vless") | .users[0].uuid // empty' "$CONFIG_PATH" | head -n1 || true)
    REALITY_PK=$(jq -r '.inbounds[] | select(.type=="vless") | .tls.reality.private_key // empty' "$CONFIG_PATH" | head -n1 || true)
    REALITY_SID=$(jq -r '.inbounds[] | select(.type=="vless") | .tls.reality.short_id[0] // empty' "$CONFIG_PATH" | head -n1 || true)

    # fallback defaults
    SS_PORT="${SS_PORT:-}"
    SS_PSK="${SS_PSK:-}"
    SS_METHOD="${SS_METHOD:-}"
    HY2_PORT="${HY2_PORT:-}"
    HY2_PSK="${HY2_PSK:-}"
    TUIC_PORT="${TUIC_PORT:-}"
    TUIC_UUID="${TUIC_UUID:-}"
    TUIC_PSK="${TUIC_PSK:-}"
    REALITY_PORT="${REALITY_PORT:-}"
    REALITY_UUID="${REALITY_UUID:-}"
    REALITY_PK="${REALITY_PK:-}"
    REALITY_SID="${REALITY_SID:-}"
}

# get public IP (tries multiple endpoints)
get_public_ip() {
    local ip=""
    for url in "https://api.ipify.org" "https://ipinfo.io/ip" "https://ifconfig.me" "https://icanhazip.com" "https://ipecho.net/plain"; do
        ip=$(curl -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        if [ -n "$ip" ]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

# generate and save URIs
generate_and_save_uris() {
    read_config_fields || return 1

    PUBLIC_IP=$(get_public_ip || true)
    [ -z "$PUBLIC_IP" ] && PUBLIC_IP="YOUR_SERVER_IP"
    
    # 读取文件内容作为节点后缀
    node_suffix=$(cat /root/node_names.txt 2>/dev/null || true)

    # SS: two formats: percent-encoded userinfo and base64 userinfo
    ss_userinfo="${SS_METHOD}:${SS_PSK}"
    ss_encoded=$(url_encode_min "$ss_userinfo")
    ss_b64=$(printf "%s" "$ss_userinfo" | base64 -w0 2>/dev/null || printf "%s" "$ss_userinfo" | base64 | tr -d '\n')
    hy2_encoded=$(url_encode_min "$HY2_PSK")
    tuic_encoded=$(url_encode_min "$TUIC_PSK")

    # reality pubkey read file or from config (fallback)
    if [ -f "$REALITY_PUB_FILE" ]; then
        REALITY_PUB=$(cat "$REALITY_PUB_FILE")
    else
        REALITY_PUB=$(jq -r '.inbounds[] | select(.type=="vless") | .tls.reality.public_key // empty' "$CONFIG_PATH" | head -n1 || true)
        REALITY_PUB="${REALITY_PUB:-UNKNOWN}"
    fi

    {
        echo "=== Shadowsocks (SS) ==="
        echo "ss://${ss_encoded}@${PUBLIC_IP}:${SS_PORT}#ss${node_suffix}"
        echo "ss://${ss_b64}@${PUBLIC_IP}:${SS_PORT}#ss${node_suffix}"
        echo ""
        echo "=== Hysteria2 (HY2) ==="
        echo "hy2://${hy2_encoded}@${PUBLIC_IP}:${HY2_PORT}/?sni=www.bing.com&alpn=h3&insecure=1#hy2${node_suffix}"
        echo ""
        echo "=== TUIC ==="
        echo "tuic://${TUIC_UUID}:${tuic_encoded}@${PUBLIC_IP}:${TUIC_PORT}/?congestion_control=bbr&alpn=h3&sni=www.bing.com&insecure=1#tuic${node_suffix}"
        echo ""
        echo "=== VLESS Reality ==="
        echo "vless://${REALITY_UUID}@${PUBLIC_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=addons.mozilla.org&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}#reality${node_suffix}"
    } > "$URI_PATH"

    info "URI 已写入: $URI_PATH"
}

# view URIs (regenerate first)
action_view_uri() {
    info "正在生成并显示 URI..."
    generate_and_save_uris || { err "生成 URI 失败"; return 1; }
    echo ""
    sed -n '1,200p' "$URI_PATH" || true
}

# view config path
action_view_config() {
    echo "$CONFIG_PATH"
}

# edit config: use EDITOR or fallback
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

    # check with sing-box if available
    if command -v sing-box >/dev/null 2>&1; then
        if sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1; then
            info "配置校验通过，尝试重启服务"
            service_restart || warn "重启失败"
            generate_and_save_uris || true
        else
            warn "配置校验失败，服务未重启"
        fi
    else
        warn "未检测到 sing-box，可跳过校验"
    fi
}

# Reset SS based on current config
action_reset_ss() {
    read_config_fields || return 1

    read -p "输入新的 SS 端口（回车保持 $SS_PORT）: " new_ss_port
    [ -z "$new_ss_port" ] && new_ss_port="$SS_PORT"

    read -p "输入新的 SS 密码（回车随机生成）: " new_ss_psk
    [ -z "$new_ss_psk" ] && new_ss_psk=$(rand_b64)

    info "正在停止服务..."
    service_stop || warn "停止服务失败"

    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"

    jq --argjson port "$new_ss_port" --arg psk "$new_ss_psk" '
    .inbounds |= map(
        if .type=="shadowsocks" then
            .listen_port = $port |
            .password = $psk
        else .
        end
    )
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"

    info "已更新 SS 端口($new_ss_port)与密码(隐藏)，正在启动服务..."
    service_start || warn "启动服务失败"
    sleep 1
    generate_and_save_uris || warn "生成 URI 失败"
}

# Reset HY2 based on current config
action_reset_hy2() {
    read_config_fields || return 1

    read -p "输入新的 HY2 端口（回车保持 $HY2_PORT）: " new_hy2_port
    [ -z "$new_hy2_port" ] && new_hy2_port="$HY2_PORT"

    read -p "输入新的 HY2 密码（回车随机生成）: " new_hy2_psk
    [ -z "$new_hy2_psk" ] && new_hy2_psk=$(rand_b64)

    info "正在停止服务..."
    service_stop || warn "停止服务失败"

    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"

    jq --argjson port "$new_hy2_port" --arg psk "$new_hy2_psk" '
    .inbounds |= map(
        if .type=="hysteria2" then
            .listen_port = $port |
            (.users[0].password) = $psk
        else .
        end
    )
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"

    info "已更新 HY2 端口($new_hy2_port)与密码(隐藏)，正在启动服务..."
    service_start || warn "启动服务失败"
    sleep 1
    generate_and_save_uris || warn "生成 URI 失败"
}

# Reset TUIC based on current config
action_reset_tuic() {
    read_config_fields || return 1

    read -p "输入新的 TUIC 端口（回车保持 $TUIC_PORT）: " new_tuic_port
    [ -z "$new_tuic_port" ] && new_tuic_port="$TUIC_PORT"

    read -p "输入新的 TUIC UUID（回车随机生成）: " new_tuic_uuid
    [ -z "$new_tuic_uuid" ] && new_tuic_uuid=$(rand_uuid)

    read -p "输入新的 TUIC 密码（回车随机生成）: " new_tuic_psk
    [ -z "$new_tuic_psk" ] && new_tuic_psk=$(rand_b64)

    info "正在停止服务..."
    service_stop || warn "停止服务失败"

    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"

    jq --argjson port "$new_tuic_port" --arg uuid "$new_tuic_uuid" --arg psk "$new_tuic_psk" '
    .inbounds |= map(
        if .type=="tuic" then
            .listen_port = $port |
            (.users[0].uuid) = $uuid |
            (.users[0].password) = $psk
        else .
        end
    )
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"

    info "已更新 TUIC 端口($new_tuic_port)、UUID(隐藏)与密码(隐藏)，正在启动服务..."
    service_start || warn "启动服务失败"
    sleep 1
    generate_and_save_uris || warn "生成 URI 失败"
}

# Reset Reality based on current config
action_reset_reality() {
    read_config_fields || return 1

    read -p "输入新的 Reality 端口（回车保持 $REALITY_PORT）: " new_reality_port
    [ -z "$new_reality_port" ] && new_reality_port="$REALITY_PORT"

    read -p "输入新的 Reality UUID（回车随机生成）: " new_reality_uuid
    [ -z "$new_reality_uuid" ] && new_reality_uuid=$(rand_uuid)

    info "正在停止服务..."
    service_stop || warn "停止服务失败"

    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"

    jq --argjson port "$new_reality_port" --arg uuid "$new_reality_uuid" '
    .inbounds |= map(
        if .type=="vless" then
            .listen_port = $port |
            (.users[0].uuid) = $uuid
        else .
        end
    )
    ' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"

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
            warn "apk 更新失败，尝试官方安装脚本"
            bash <(curl -fsSL https://sing-box.app/install.sh) || { err "更新失败"; return 1; }
        }
    else
        bash <(curl -fsSL https://sing-box.app/install.sh) || { err "更新失败"; return 1; }
    fi

    info "更新完成，尝试重启服务..."
    if command -v sing-box >/dev/null 2>&1; then
        NEW_VER=$(sing-box version 2>/dev/null | head -n1 || echo "unknown")
        info "当前 sing-box 版本: $NEW_VER"
        service_restart || warn "重启失败"
    else
        warn "更新后未检测到 sing-box 可执行文件"
    fi
}

# Uninstall sing-box
action_uninstall() {
    read -p "确认卸载 sing-box？(y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "已取消卸载"
        return 0
    fi

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
    rm -f /root/node_names.txt >/dev/null 2>&1 || true
    info "卸载完成"
}

# Generate relay script (SS out)
action_generate_relay_script() {
    read_config_fields || return 1

    PUBLIC_IP=$(get_public_ip || true)
    [ -z "$PUBLIC_IP" ] && PUBLIC_IP="YOUR_SERVER_IP"

    RELAY_SCRIPT_PATH="/tmp/relay-install.sh"

    info "正在生成线路机脚本: $RELAY_SCRIPT_PATH"

    cat > "$RELAY_SCRIPT_PATH" <<'RELAY_TEMPLATE'
#!/usr/bin/env bash
set -euo pipefail

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

if [ "$(id -u)" != "0" ]; then err "必须以 root 运行"; exit 1; fi

detect_os(){
    . /etc/os-release 2>/dev/null || true
    case "$ID" in
        alpine) OS=alpine ;;
        debian|ubuntu) OS=debian ;;
        centos|rhel|fedora) OS=redhat ;;
        *) OS=unknown ;;
    esac
}
detect_os

install_deps(){
    case "$OS" in
        alpine) apk update; apk add --no-cache curl jq bash openssl ca-certificates ;;
        debian) apt-get update -y; apt-get install -y curl jq bash openssl ca-certificates ;;
        redhat) yum install -y curl jq bash openssl ca-certificates ;;
    esac
}
install_deps

install_singbox(){
    case "$OS" in
        alpine) apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community sing-box ;;
        *) bash <(curl -fsSL https://sing-box.app/install.sh) ;;
    esac
}
install_singbox

UUID=$(cat /proc/sys/kernel/random/uuid)

info "生成 Reality 密钥对"
REALITY_KEYS=$(sing-box generate reality-keypair 2>/dev/null || true)
REALITY_PK=$(echo "$REALITY_KEYS" | grep "PrivateKey" | awk '{print $NF}' || true)
REALITY_PUB=$(echo "$REALITY_KEYS" | grep "PublicKey" | awk '{print $NF}' || true)
REALITY_SID=$(sing-box generate rand 8 --hex 2>/dev/null || echo "")
info "Reality PK: $REALITY_PK"
info "Reality PUB: $REALITY_PUB"
info "Reality SID: $REALITY_SID"

read -p "输入线路机监听端口（留空随机 20000-65000）: " USER_PORT
if [ -z "$USER_PORT" ]; then
    LISTEN_PORT=$(shuf -i 20000-65000 -n 1 2>/dev/null || echo $((RANDOM % 45001 + 20000)))
else
    LISTEN_PORT="$USER_PORT"
fi

mkdir -p /etc/sing-box

cat > /etc/sing-box/config.json <<EOF
{
  "log": { "level": "info", "timestamp": true },
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
          "short_id": [ "$REALITY_SID" ]
        }
      },
      "tag": "vless-in"
    }
  ],
  "outbounds": [
    {
      "type": "shadowsocks",
      "server": "__INBOUND_IP__",
      "server_port": __INBOUND_PORT__,
      "method": "__INBOUND_METHOD__",
      "password": "__INBOUND_PASSWORD__",
      "tag": "relay-out"
    },
    { "type": "direct", "tag": "direct-out" }
  ],
  "route": { "rules": [ { "inbound": "vless-in", "outbound": "relay-out" } ] }
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
info "✅ 安装完成"
echo "===================== 中转节点 Reality 链接 ====================="
echo "vless://$UUID@$PUB_IP:$LISTEN_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=addons.mozilla.org&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID#relay"
echo "=================================================================="
echo ""

RELAY_TEMPLATE

    sed -i "s|__INBOUND_IP__|$PUBLIC_IP|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_PORT__|$SS_PORT|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_METHOD__|$SS_METHOD|g" "$RELAY_SCRIPT_PATH"
    sed -i "s|__INBOUND_PASSWORD__|$SS_PSK|g" "$RELAY_SCRIPT_PATH"

    chmod +x "$RELAY_SCRIPT_PATH"

    info "✅ 线路机脚本已生成：$RELAY_SCRIPT_PATH"
    echo ""
    info "请手动复制以下内容到线路机，保存为 /tmp/relay-install.sh，并执行：chmod +x /tmp/relay-install.sh && bash /tmp/relay-install.sh"
    echo "------------------------------------------"
    cat "$RELAY_SCRIPT_PATH"
    echo "------------------------------------------"
    echo ""
    info "在线路机执行命令示例："
    echo "   nano /tmp/relay-install.sh 保存后执行"
    echo "   chmod +x /tmp/relay-install.sh && bash /tmp/relay-install.sh"
    echo ""
    info "复制完成后，即可在线路机完成 sing-box 中转节点部署。"
}

# Main menu
while true; do
    cat <<'MENU'

==========================
 Sing-box 管理面板 (快捷指令sb)
==========================
1) 查看协议链接 (SS/HY2/TUIC/Reality)
2) 查看配置文件路径
3) 编辑配置文件
4) 重置 SS 端口/密码
5) 重置 HY2 端口/密码
6) 重置 TUIC 端口/UUID/密码
7) 重置 Reality 端口/UUID
8) 启动服务
9) 停止服务
10) 重启服务
11) 查看状态
12) 更新 sing-box
13) 生成线路机出口脚本 (SS出站)
14) 卸载 sing-box
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
        6) action_reset_tuic ;;
        7) action_reset_reality ;;
        8) service_start && info "已发送启动命令" ;;
        9) service_stop && info "已发送停止命令" ;;
        10) service_restart && info "已发送重启命令" ;;
        11) service_status ;;
        12) action_update ;;
        13) action_generate_relay_script ;;
        14) action_uninstall; exit 0 ;;
        0) exit 0 ;;
        *) warn "无效选项" ;;
    esac

    echo ""
done
SB_SCRIPT

chmod +x "$SB_PATH" || warn "无法设置 $SB_PATH 为可执行"

info "快捷指令已创建：可输入 sb 运行管理面板"

# end of script
