#!/usr/bin/env bash
set -euo pipefail

# -----------------------
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

# -----------------------
# detect OS
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
    else
        OS="unknown"
    fi
}
detect_os
info "检测到系统类型: $OS"

# -----------------------
# prompt port / password
read -p "请输入端口（留空则随机 10000-60000）: " USER_PORT
if [ -z "$USER_PORT" ]; then
    PORT=$(shuf -i 10000-60000 -n 1)
    info "使用随机端口: $PORT"
else
    if ! [[ "$USER_PORT" =~ ^[0-9]+$ ]] || [ "$USER_PORT" -lt 1 ] || [ "$USER_PORT" -gt 65535 ]; then
        err "端口必须为 1-65535 的数字"
        exit 1
    fi
    PORT="$USER_PORT"
fi

read -p "请输入密码（留空则自动生成符合 SS2022 要求的 Base64 密钥）: " USER_PWD

# -----------------------
# install sing-box
install_singbox() {
    info "安装 sing-box（调用官方安装脚本）"
    if [ "$OS" = "alpine" ]; then
        info "Alpine 环境：确保 bash/curl 可用"
        apk add --no-cache bash curl ca-certificates openssl || err "apk 安装依赖失败"
        bash -c "$(curl -fsSL https://sing-box.app/install.sh | sh -s -- --version 1.11.11)"
    elif [ "$OS" = "debian" ]; then
        apt-get update -y
        apt-get install -y curl ca-certificates openssl || err "apt 安装依赖失败"
        bash -c "$(curl -fsSL https://sing-box.app/install.sh | sh -s -- --version 1.11.11)"
    else
        warn "未检测到受支持的发行版 (alpine/debian)。尝试直接运行官方安装脚本。"
        bash -c "$(curl -fsSL https://sing-box.app/install.sh | sh -s -- --version 1.11.11)"
    fi
}

install_singbox

# -----------------------
# generate password
KEY_BYTES=16
METHOD="2022-blake3-aes-128-gcm"

generate_psk() {
    if [ -n "${USER_PWD:-}" ]; then
        PSK="$USER_PWD"
        info "使用你输入的密码，请确保 Base64 长度符合协议"
    else
        if command -v sing-box >/dev/null 2>&1; then
            PSK=$(sing-box generate rand --base64 "$KEY_BYTES" | tr -d '\n' || true)
        fi
        if [ -z "${PSK:-}" ]; then
            if command -v openssl >/dev/null 2>&1; then
                PSK=$(openssl rand -base64 "$KEY_BYTES" | tr -d '\n')
            else
                PSK=$(python3 - <<PY
import base64,os
print(base64.b64encode(os.urandom($KEY_BYTES)).decode())
PY
)
            fi
        fi
        info "自动生成 PSK: $PSK"
    fi
}

generate_psk

# -----------------------
# config
CONFIG_PATH="/etc/sing-box/config.json"
mkdir -p "$(dirname "$CONFIG_PATH")"
cat > "$CONFIG_PATH" <<EOF
{
  "log": {"level":"info"},
  "inbounds":[{"type":"shadowsocks","listen":"::","listen_port":$PORT,"method":"$METHOD","password":"$PSK","tag":"ss2022-in"}],
  "outbounds":[{"type":"direct","tag":"direct-out"}]
}
EOF
info "配置写入 $CONFIG_PATH"

# -----------------------
# service
if [ "$OS" = "alpine" ]; then
    SERVICE_PATH="/etc/init.d/sing-box"
    info "生成 OpenRC 服务: $SERVICE_PATH"
    cat > "$SERVICE_PATH" <<'EOF'
#!/sbin/openrc-run
command=/usr/bin/sing-box
command_args="run -c /etc/sing-box/config.json"
pidfile=/run/sing-box.pid
name=sing-box
description="Sing-box Shadowsocks Server"
EOF
    chmod +x "$SERVICE_PATH"
    rc-update add sing-box default
    rc-service sing-box start
    info "OpenRC 服务已启动并添加开机自启"
elif command -v systemctl >/dev/null 2>&1; then
    SERVICE_PATH="/etc/systemd/system/sing-box.service"
    info "生成 systemd 服务: $SERVICE_PATH"
    cat > "$SERVICE_PATH" <<'UNIT'
[Unit]
Description=Sing-box Shadowsocks Server
After=network.target
[Service]
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now sing-box || warn "systemd 服务启动失败，请手动运行"
fi

# -----------------------
# 获取公网 IP
get_public_ip() {
    for url in "https://ipinfo.io/ip" "https://ipv4.icanhazip.com" "https://ifconfig.co/ip" "https://api.ipify.org"; do
        PUBIP=$(curl -s --max-time 5 "$url" || true)
        if [ -n "$PUBIP" ]; then
            echo "$PUBIP" | tr -d '[:space:]'
            return 0
        fi
    done
    return 1
}

PUB_IP="$(get_public_ip || true)"
if [ -z "$PUB_IP" ]; then
    warn "无法自动获取公网 IP，请手动使用服务器 IP 生成客户端链接"
    PUB_IP="YOUR_SERVER_IP"
else
    info "检测到公网 IP: $PUB_IP"
fi

# -----------------------
# 生成 SS URI
make_ss_links() {
    HOST="$PUB_IP"
    TAG="singbox-ss2022"
    USERINFO="${METHOD}:${PSK}"

    if command -v python3 >/dev/null 2>&1; then
        ENC_USERINFO=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$USERINFO")
        BASE64_USERINFO=$(python3 -c "import base64,sys; s=sys.argv[1].encode(); print(base64.b64encode(s).decode())" "$USERINFO")
    else
        ENC_USERINFO=$(printf "%s" "$USERINFO" | jq -s -R -r @uri 2>/dev/null || printf "%s" "$USERINFO")
        BASE64_USERINFO=$(printf "%s" "$USERINFO" | base64 | tr -d '\n')
    fi

    SS_SIP002="ss://${ENC_USERINFO}@${HOST}:${PORT}#${TAG}"
    SS_BASE64="ss://${BASE64_USERINFO}@${HOST}:${PORT}#${TAG}"

    echo "$SS_SIP002"
    echo "$SS_BASE64"
}

# -----------------------
# 输出
info ""
info "==================== 生成的 ss 链接 ===================="
make_ss_links | sed -e 's/^/    /'
info "======================================================="

info "部署完成 ✅"
info "端口: $PORT"
info "PSK: $PSK"
info "配置文件: $CONFIG_PATH"
info "服务路径: ${SERVICE_PATH:-手动启动}"
