# Sing-box 多协议一键部署脚本

一个强大的 Sing-box 自动化部署工具，支持SS2022/HY2/VLESS Reality 部署和线路机 VLESS Reality 中转的完整解决方案。

---

## ✨ 主要特性

### 🎯 部署机功能

- ✅ **一键安装** - 自动部署 Sing-box 最新服务端
- ✅ **密钥生成** - 自动生成 密钥和配置文件
- ✅ **多系统支持** - 支持 Alpine, Debian, Ubuntu, CentOS, RHEL, Fedora 等操作系统
- ✅ **开机自启** - 自动配置 Systemd / OpenRC 开机自启
- ✅ **公网 IP** - 自动获取公网 IP 并生成客户端链接
- ✅ **管理工具** - 集成 sb 命令行工具，功能齐全

### 🔗 线路机功能

- ✅ **一键生成** - 从落地机直接生成线路机安装脚本
- ✅ **Reality 入站** - 自动部署 VLESS + TLS Reality 入站
- ✅ **灵活端口** - 支持自动寻找空闲端口或手动指定
- ✅ **流量转发** - 自动转发流量到落地机节点
- ✅ **完整链接** - 生成可用的 VLESS Reality 客户端链接

## 🙏 致谢 · Acknowledgements

[![sponsor](https://img.shields.io/badge/Sponsor-懒猫云-brightgreen)]()  
[![sponsor](https://img.shields.io/badge/Sponsor-拼垃圾-brightgreen)]()

本项目能够顺利完成，离不开 **懒猫云** 与 **拼垃圾** 的支持。  
非常感谢他们提供的赞助与鼓励。  
**真心感谢！**

## ✅ 一键部署命令

安装全功能 sing-box：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/caigouzi121380/singbox-deploy/main/install-singbox-yyds.sh)"
