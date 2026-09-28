# Surge VLESS Bridge Hub (fuck-surge)

为 macOS 上的 **Surge** 提供无缝使用 **VLESS (Reality / Vision / WebSocket / gRPC)** 节点的本地轻量中枢面板。

![ScreenShot_2026-09-28_161050_808](https://github.com/ceocok/fuck-surge/blob/main/ScreenShot_2026-09-28_161050_808.png)

---

## 💡 为什么需要它？

Surge 是一款优秀的 macOS 规则分流与网络调试工具，但受限于闭源架构与安全机制，原生无法支持 VLESS / Reality 协议。

**Fuck-Surge** 通过在本地运行专用的轻量 Xray 内核，将每个 VLESS 节点自动映射为本地独立的 SOCKS5 入站端口（`127.0.0.1:10810`, `10811`, ...），并自动为 Surge 生成开箱即用的配置代码。

> 流量路径：
> **应用程序** $\xrightarrow{\text{Surge 规则分流}}$ **本地 127.0.0.1:1081x (SOCKS5)** $\xrightarrow{\text{本地 Xray (VLESS/Reality)}}$ **远端服务器**

这样既能继续享受 Surge 强大的规则系统、Dashboard 抓包和虚拟网卡（Enhanced Mode / TUN），又完美支持了 VLESS 协议！

---

## ✨ 核心特性

1. **一键批量解析**：直接粘贴单条或多条 `vless://` 链接，自动解析协议、UUID、Reality 公钥及 SNI。
2. **多端口独立映射**：每个节点独立分配本地端口，互不冲突，支持在 Surge 中单独使用或加入策略组。
3. **Surge 一键配置生成**：
   - 自动生成 `[Proxy]` 节点配置。
   - 自动生成 `[Proxy Group]` 策略组（支持手动选择与 `url-test` 自动容灾优选）。
4. **内置实时测速**：面板内一键检测各个节点的真实网络延迟。
5. **本地配置持久化**：重启后自动加载保存的节点。

---

## 🛠️ 环境准备

运行前请确保本地安装了 `xray`（推荐通过 Homebrew 安装）：

```bash
brew install xray
```

---

## 🚀 快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/ceocok/fuck-surge.git
cd fuck-surge

# 2. 赋予脚本执行权限并启动
chmod +x *.sh
./start.sh
```

启动后会自动打开浏览器访问管理面板：
👉 **http://127.0.0.1:9099**

---

## 📖 极简使用 3 步

1. **粘贴节点**：在面板左侧输入框粘贴你的 `vless://` 链接（支持多行），点击 **“⚡ 解析并启动/应用”**。
2. **复制配置**：点击面板下方的 **“复制 [Proxy] 配置”** 和 **“复制 [Proxy Group] 配置”**。
3. **粘贴到 Surge**：
   - 打开 Surge for Mac，点击顶部菜单栏图标。
   - 选择 **配置文件 (Profiles) $\rightarrow$ 文本编辑 (Edit in Text Editor)**。
   - 将复制的内容分别粘贴至 `[Proxy]` 和 `[Proxy Group]` 区域并保存即可！

---

## 🛑 管理命令

```bash
# 启动面板并在浏览器打开
./start.sh

# 停止面板与 Xray 内核
./stop.sh
```
