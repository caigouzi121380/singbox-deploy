# Sing-box 多协议一键部署脚本

一个强大的 Sing-box 自动化部署工具，支持SS2022/HY2/TUIC/VLESS Reality 协议自选部署和线路机 VLESS Reality 中转的完整解决方案。

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

## 🙏 特别鸣谢以下商家对本项目的赞助支持

<div align="center">

<table>
  <tr>
    <td align="center" width="220">
      <a href="https://console.alice.sh/" target="_blank">
        <img src="https://console.alice.sh/assets/images/logo-yellow.svg" width="100" alt="AliceNetworks" />
        <br><sub><b>AliceNetworks</b></sub>
      </a>
    </td>
    <td align="center" width="220">
      <a href="https://lxc.lazycats.online/" target="_blank">
        <img src="https://lxc.lazycats.online/themes/web/yunyoo/assets/img/logo/logo.png" width="100" alt="懒猫云" />
        <br><sub><b>懒猫云</b></sub>
      </a>
    </td>
    <td align="center" width="220">
      <a href="https://www.lxc.wiki/" target="_blank">
        <img src="https://www.lxc.wiki/themes/web/starvm-phj/img/logo.png" width="100" alt="拼好鸡" />
        <br><sub><b>拼好鸡</b></sub>
      </a>
    </td>
  </tr>
</table>

</div>


## ✅ 一键部署命令

安装全功能 sing-box：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/caigouzi121380/singbox-deploy/main/install-singbox-yyds.sh)"
