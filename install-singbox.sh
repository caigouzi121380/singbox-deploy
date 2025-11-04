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
            apk add --no-cache bash curl ca-certificates openssl openrc || {
                err "依赖安装失败"
                exit 1
            }
            
            # 确保 OpenRC 运行
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
# 端口和密码输入（支持环境变量）
get_config() {
    # 支持通过环境变量传参，方便自动化部署
    if [ -n "${SINGBOX_PORT:-}" ]; then
        PORT="$SINGBOX_PORT"
        info "使用环境变量端口: $PORT"
    else
        echo ""
        read -p "请输入端口（留空则随机 10000-60000）: " USER_PORT
        if [ -z "$USER_PORT" ]; then
            PORT=$(shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50001 + 10000)))
            info "使用随机端口: $PORT"
        else
            if ! [[ "$USER_PORT" =~ ^[0-9]+$ ]] || [ "$USER_PORT" -lt 1 ] || [ "$USER_PORT" -gt 65535 ]; then
                err "端口必须为 1-65535 的数字"
                exit 1
            fi
            PORT="$USER_PORT"
        fi
    fi

    if [ -n "${SINGBOX_PASSWORD:-}" ]; then
        USER_PWD="$SINGBOX_PASSWORD"
        info "使用环境变量密码"
    else
        echo ""
        read -p "请输入密码（留空则自动生成 Base64 密钥）: " USER_PWD
    fi
}

get_config

# -----------------------
# 安装 sing-box
install_singbox() {
    info "开始安装 sing-box..."

    # 检查是否已安装
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
            # 原官方安装脚本
            bash <(curl -fsSL https://sing-box.app/install.sh) || {
                err "sing-box 安装失败"
                err "请检查网络连接或手动安装"
                exit 1
            }
            ;;
        *)
            err "未支持的系统，无法安装 sing-box"
            exit 1
            ;;
    esac

    # 验证安装
    if ! command -v sing-box >/dev/null 2>&1; then
        err "sing-box 安装后未找到可执行文件"
        exit 1
    fi

    INSTALLED_VERSION=$(sing-box version 2>/dev/null | head -1 || echo "unknown")
    info "sing-box 安装成功: $INSTALLED_VERSION"
}

install_singbox

# -----------------------
# 生成密码
KEY_BYTES=16
METHOD="2022-blake3-aes-128-gcm"

generate_psk() {
    if [ -n "${USER_PWD:-}" ]; then
        PSK="$USER_PWD"
        info "使用指定密码"
    else
        info "自动生成密码..."
        
        # 优先使用 sing-box
        if command -v sing-box >/dev/null 2>&1; then
            PSK=$(sing-box generate rand --base64 "$KEY_BYTES" 2>/dev/null | tr -d '\n\r' || true)
        fi
        
        # 备选: openssl
        if [ -z "${PSK:-}" ] && command -v openssl >/dev/null 2>&1; then
            PSK=$(openssl rand -base64 "$KEY_BYTES" | tr -d '\n\r')
        fi
        
        # 最后备选: /dev/urandom
        if [ -z "${PSK:-}" ]; then
            PSK=$(head -c "$KEY_BYTES" /dev/urandom | base64 | tr -d '\n\r')
        fi
        
        if [ -z "${PSK:-}" ]; then
            err "密码生成失败"
            exit 1
        fi
        
        info "密码生成成功"
    fi
}

generate_psk

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
      "listen_port": $PORT,
      "method": "$METHOD",
      "password": "$PSK",
      "tag": "ss2022-in"
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

    # 验证配置
    if command -v sing-box >/dev/null 2>&1; then
        if sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1; then
            info "配置文件验证通过"
        else
            warn "配置文件验证失败，但将继续..."
        fi
    fi
}

create_config

# -----------------------
# 设置服务
setup_service() {
    info "配置系统服务..."
    
    if [ "$OS" = "alpine" ]; then
        # Alpine OpenRC 服务
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

start_post() {
    sleep 1
    if [ -f "$pidfile" ]; then
        einfo "Sing-box started successfully (PID: $(cat $pidfile))"
    else
        ewarn "Sing-box may not have started correctly"
    fi
}
OPENRC
        
        chmod +x "$SERVICE_PATH"
        
        # 添加到开机自启
        rc-update add sing-box default >/dev/null 2>&1 || warn "添加开机自启失败"
        
        # 启动服务
        rc-service sing-box restart || {
            err "服务启动失败，查看日志："
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
        # Systemd 服务
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
            err "服务启动失败，查看日志："
            journalctl -u sing-box -n 30 --no-pager
            exit 1
        }
        
        sleep 2
        
        if systemctl is-active sing-box >/dev/null 2>&1; then
            info "✅ Systemd 服务已启动"
        else
            err "服务状态异常"
            systemctl status sing-box --no-pager
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
# 生成 SS URI
generate_uri() {
    local host="$PUB_IP"
    local tag="singbox-ss2022"
    local userinfo="${METHOD}:${PSK}"
    
    # SIP002 格式 (URL编码)
    local encoded_userinfo
    if command -v python3 >/dev/null 2>&1; then
        encoded_userinfo=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$userinfo" 2>/dev/null || echo "$userinfo")
    else
        encoded_userinfo=$(printf "%s" "$userinfo" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
    fi
    
    # Base64 格式
    local base64_userinfo=$(printf "%s" "$userinfo" | base64 -w0 2>/dev/null || printf "%s" "$userinfo" | base64 | tr -d '\n')
    
    echo "ss://${encoded_userinfo}@${host}:${PORT}#${tag}"
    echo "ss://${base64_userinfo}@${host}:${PORT}#${tag}"
}

# -----------------------
# 最终输出
echo ""
echo "=========================================="
info "🎉 Sing-box 部署完成！"
echo "=========================================="
echo ""
info "📋 配置信息："
echo "   端口: $PORT"
echo "   方法: $METHOD"
echo "   密码: $PSK"
echo "   服务器: $PUB_IP"
echo ""
info "📁 文件位置："
echo "   配置: $CONFIG_PATH"
echo "   服务: $SERVICE_PATH"
echo ""
info "🔗 客户端链接："
generate_uri | while IFS= read -r line; do
    echo "   $line"
done
echo ""
info "🔧 管理命令："
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
# (Do not modify other parts of the original script; sb is added as a separate tool)
# -----------------------
# Create sb management script (重置端口/密码已删除)
SB_PATH="/usr/local/bin/sb"
info "正在创建 sb 管理脚本: $SB_PATH"

cat > "$SB_PATH" <<'SB_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

CONFIG_PATH="/etc/sing-box/config.json"
SS_URI_PATH="/etc/sing-box/ss_uri.txt"
BIN_PATH="/usr/bin/sing-box"
SERVICE_NAME="sing-box"

detect_os() {
    if [ -f /etc/os-release ]; then . /etc/os-release; ID="${ID:-}"; ID_LIKE="${ID_LIKE:-}"; else ID=""; ID_LIKE=""; fi
    if echo "$ID $ID_LIKE" | grep -qi "alpine"; then OS="alpine"
    elif echo "$ID $ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then OS="debian"
    elif echo "$ID $ID_LIKE" | grep -Ei "centos|rhel|fedora" >/dev/null; then OS="redhat"
    else OS="unknown"; fi
}
detect_os

service_start() { [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" start || systemctl start "$SERVICE_NAME"; }
service_stop()  { [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" stop  || systemctl stop "$SERVICE_NAME"; }
service_restart(){ [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" restart || systemctl restart "$SERVICE_NAME"; }
service_status(){ [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" status  || systemctl status "$SERVICE_NAME" --no-pager; }

read_config_fields() {
    [ ! -f "$CONFIG_PATH" ] && { err "未找到配置文件"; return 1; }
    if command -v python3 >/dev/null 2>&1; then
        METHOD=$(python3 -c 'import json; c=json.load(open("'"$CONFIG_PATH"'")); print(c["inbounds"][0].get("method",""))')
        PSK=$(python3 -c 'import json; c=json.load(open("'"$CONFIG_PATH"'")); print(c["inbounds"][0].get("password",""))')
        PORT=$(python3 -c 'import json; c=json.load(open("'"$CONFIG_PATH"'")); print(c["inbounds"][0].get("listen_port",""))')
    else
        METHOD=$(grep -m1 '"method"' "$CONFIG_PATH" 2>/dev/null | sed -E 's/.*"method"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' || true)
        PSK=$(grep -m1 '"password"' "$CONFIG_PATH" 2>/dev/null | sed -E 's/.*"password"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' || true)
        PORT=$(grep -m1 '"listen_port"' "$CONFIG_PATH" 2>/dev/null | sed -E 's/.*"listen_port"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/' || true)
    fi
}

generate_and_save_uri() {
    read_config_fields || return 1
    PUBLIC_IP=""
    for url in "https://api.ipify.org" "https://ipinfo.io/ip" "https://ifconfig.me" "https://icanhazip.com" "https://ipecho.net/plain"; do
        PUBLIC_IP=$(curl -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        [ -n "$PUBLIC_IP" ] && break
    done
    [ -z "$PUBLIC_IP" ] && PUBLIC_IP="YOUR_SERVER_IP"
    userinfo="${METHOD}:${PSK}"
    if command -v python3 >/dev/null 2>&1; then
        encoded_userinfo=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$userinfo")
    else
        encoded_userinfo=$(printf "%s" "$userinfo" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
    fi
    base64_userinfo=$(printf "%s" "$userinfo" | base64 -w0 2>/dev/null || printf "%s" "$userinfo" | base64 | tr -d '\n')
    echo "ss://${encoded_userinfo}@${PUBLIC_IP}:${PORT}#singbox-ss2022" > "$SS_URI_PATH"
    echo "ss://${base64_userinfo}@${PUBLIC_IP}:${PORT}#singbox-ss2022" >> "$SS_URI_PATH"
    info "SS URI 已写入: $SS_URI_PATH"
}

action_view_uri() { [ -f "$SS_URI_PATH" ] && sed -n '1,200p' "$SS_URI_PATH" || (warn "未找到 URI，尝试生成..."; generate_and_save_uri && sed -n '1,200p' "$SS_URI_PATH"); }
action_view_config() { echo "$CONFIG_PATH"; }
action_edit_config() { [ ! -f "$CONFIG_PATH" ] && { err "配置文件不存在"; return 1; }; ${EDITOR:-nano} "$CONFIG_PATH"; command -v sing-box >/dev/null 2>&1 && sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1 && service_restart && generate_and_save_uri || warn "配置校验失败"; }

action_update() { info "开始更新 sing-box..."; [ "$OS" = "alpine" ] && { apk update || warn "apk update 失败"; apk add --upgrade --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community sing-box || bash <(curl -fsSL https://sing-box.app/install.sh) || err "更新失败"; } || bash <(curl -fsSL https://sing-box.app/install.sh) || err "更新失败"; [ -x "$(command -v sing-box)" ] && service_restart; info "更新完成"; }

action_uninstall() {
    info "正在卸载 sing-box（直接全部删除，无确认）..."
    service_stop || true

    if [ "$OS" = "alpine" ]; then
        rc-update del "$SERVICE_NAME" default >/dev/null 2>&1 || true
        [ -f "/etc/init.d/$SERVICE_NAME" ] && rm -f "/etc/init.d/$SERVICE_NAME"
    else
        systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
        [ -f "/etc/systemd/system/$SERVICE_NAME.service" ] && rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi

    # 删除配置、日志、可执行文件
    rm -rf /etc/sing-box >/dev/null 2>&1 || true
    rm -f /var/log/sing-box.log /var/log/sing-box.err >/dev/null 2>&1 || true
    rm -f "$SS_URI_PATH" >/dev/null 2>&1 || true
    rm -f "$BIN_PATH" >/dev/null 2>&1 || true

    # 删除 sb 管理脚本
    [ -f "/usr/local/bin/sb" ] && rm -f "/usr/local/bin/sb"

    info "卸载完成，所有配置、日志、可执行文件及 sb 管理脚本已删除"
}

while true; do
    cat <<'MENU'

==========================
 Sing-box 管理面板 (快捷指令 sb)
==========================
1) 查看 SS URI
2) 查看配置文件路径
3) 编辑配置文件
4) 启动服务
5) 停止服务
6) 重启服务
7) 查看状态
8) 更新 sing-box
9) 卸载 sing-box（无确认）
0) 退出
==========================
MENU
    read -p "请输入选项: " opt
    case "${opt:-}" in
        1) action_view_uri ;;
        2) action_view_config ;;
        3) action_edit_config ;;
        4) service_start && info "已发送启动命令" ;;
        5) service_stop && info "已发送停止命令" ;;
        6) service_restart && info "已发送重启命令" ;;
        7) service_status ;;
        8) action_update ;;
        9) action_uninstall; exit 0 ;;
        0) exit 0 ;;
        *) warn "无效选项" ;;
    esac
    echo ""
done
SB_SCRIPT

chmod +x "$SB_PATH" || warn "无法设置 $SB_PATH 为可执行"
info "sb 已创建：请输入 sb 运行管理面板"


# end of script
