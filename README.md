# Sing-box SS2022 一键部署脚本

 **一键部署 Sing-box Shadowsocks 2022 (2022-blake3-aes-128-gcm)** 的 Bash 脚本，支持 Debian/Ubuntu 和 Alpine Linux。

## 功能

- 自动检测系统类型（Debian/Ubuntu 或 Alpine）
- 支持自定义或随机端口
- 支持自定义或自动生成 Base64 PSK（16 字节）
- 自动安装 sing-box
- 自动生成配置文件
- 支持 systemd（Debian/Ubuntu）或 OpenRC（Alpine）服务管理
- 自动获取公网 IP 并生成 SIP002 + Base64 SS 链接

---

## 一键部署

在 VPS 上直接执行以下命令：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/caigouzi121380/singbox-deploy/main/install-singbox.sh)"
