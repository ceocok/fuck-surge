#!/usr/bin/env python3
import http.server
import json
import os
import re
import shutil
import socketserver
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
TEMPLATES_DIR = BASE_DIR / "templates"
DATA_DIR.mkdir(exist_ok=True)

CONFIG_PATH = DATA_DIR / "config.json"
NODES_PATH = DATA_DIR / "nodes.json"
LOG_PATH = DATA_DIR / "xray.log"
PID_PATH = DATA_DIR / "xray.pid"

BASE_SOCKS_PORT = 10810
WEB_PORT = 9099


def find_xray_binary():
    candidates = [
        shutil.which("xray"),
        "/opt/homebrew/bin/xray",
        "/usr/local/bin/xray",
        os.path.expanduser("~/.local/bin/xray"),
        "/usr/bin/xray",
        str(BASE_DIR / "xray"),
    ]
    for c in candidates:
        if c and os.path.exists(c) and os.access(c, os.X_OK):
            return c
    return None


XRAY_BIN = find_xray_binary()


class XrayManager:
    process = None

    @classmethod
    def get_pid(cls):
        if cls.process and cls.process.poll() is None:
            return cls.process.pid
        if PID_PATH.exists():
            try:
                pid = int(PID_PATH.read_text().strip())
                # Check if process is actually running and is xray
                os.kill(pid, 0)
                return pid
            except (ValueError, OSError):
                PID_PATH.unlink(missing_ok=True)
        return None

    @classmethod
    def is_running(cls):
        return cls.get_pid() is not None

    @classmethod
    def stop(cls):
        pid = cls.get_pid()
        if pid:
            try:
                os.kill(pid, 15)  # SIGTERM
                for _ in range(20):
                    time.sleep(0.1)
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        break
                else:
                    os.kill(pid, 9)  # SIGKILL
            except OSError:
                pass
        cls.process = None
        PID_PATH.unlink(missing_ok=True)

    @classmethod
    def start(cls):
        cls.stop()
        if not XRAY_BIN:
            raise RuntimeError("未在系统中找到 xray 可执行文件，请先运行 brew install xray")
        if not CONFIG_PATH.exists():
            return False

        log_file = open(LOG_PATH, "a")
        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", str(CONFIG_PATH)],
            stdout=log_file,
            stderr=log_file,
            start_new_session=True,
        )
        cls.process = proc
        PID_PATH.write_text(str(proc.pid))
        time.sleep(0.3)
        if proc.poll() is not None:
            PID_PATH.unlink(missing_ok=True)
            raise RuntimeError("Xray 启动失败，请检查配置文件或端口是否被占用")
        return True

    @classmethod
    def test_config(cls, test_config_path: Path):
        if not XRAY_BIN:
            raise RuntimeError("未在系统中找到 xray 可执行文件")
        res = subprocess.run(
            [XRAY_BIN, "run", "-test", "-c", str(test_config_path)],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            err_msg = res.stdout.strip() or res.stderr.strip()
            # Clean up local absolute paths in error messages
            err_msg = re.sub(r"/[^\s]+/(test_config\.json|config\.json|tmp_[^\s]+)", r"[\1]", err_msg)
            err_msg = re.sub(r"/var/folders/[^\s]+", "[tmp_config]", err_msg)
            raise RuntimeError(f"Xray 配置校验失败:\n{err_msg}")
        return True


def sanitize_surge_name(name: str) -> str:
    # Surge node names shouldn't contain commas or equals
    cleaned = re.sub(r"[,=\r\n]", "_", name.strip())
    return cleaned if cleaned else "VLESS_Node"


def parse_vless_link(link: str, port: int):
    link = link.strip()
    if not link.startswith("vless://"):
        return None

    try:
        p = urllib.parse.urlsplit(link)
    except Exception:
        return None

    if p.scheme != "vless":
        return None

    uuid = p.username or ""
    server = p.hostname or ""
    server_port = p.port or 443

    if not uuid or not server:
        return None

    qs = urllib.parse.parse_qs(p.query)

    def q(k, default=""):
        val = qs.get(k)
        return val[0].strip() if val else default

    security = q("security", "none").lower()
    net = q("type", q("net", "tcp")).lower()
    flow = q("flow", "")
    sni = q("sni", q("serverName", ""))
    fp = q("fp", q("fingerprint", "chrome"))
    pbk = q("pbk", q("publicKey", ""))
    sid = q("sid", q("shortId", ""))
    spx = q("spx", q("spiderX", ""))
    path = urllib.parse.unquote(q("path", "/"))
    host_hdr = q("host", "")
    service_name = q("serviceName", "")
    mode = q("mode", "gun")
    alpn = q("alpn", "")
    encryption = q("encryption", "none")

    raw_remark = urllib.parse.unquote(p.fragment).strip() if p.fragment else ""
    node_name = sanitize_surge_name(raw_remark or f"VLESS_{server}_{port}")

    outbound = {
        "tag": f"out-{port}",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": server,
                    "port": server_port,
                    "users": [{"id": uuid, "encryption": encryption}],
                }
            ]
        },
        "streamSettings": {
            "network": net,
            "security": security,
        },
    }

    if flow:
        outbound["settings"]["vnext"][0]["users"][0]["flow"] = flow

    features = []
    if security == "reality":
        features.append("Reality")
        outbound["streamSettings"]["realitySettings"] = {
            "show": False,
            "fingerprint": fp or "chrome",
            "serverName": sni or server,
            "publicKey": pbk,
            "shortId": sid or "",
            "spiderX": spx or "",
        }
    elif security == "tls":
        features.append("TLS")
        tls_settings = {
            "serverName": sni or server,
            "fingerprint": fp or "chrome",
            "allowInsecure": False,
        }
        if alpn:
            tls_settings["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        outbound["streamSettings"]["tlsSettings"] = tls_settings

    if flow:
        features.append(flow)

    if net == "ws":
        features.append("WS")
        ws_settings = {"path": path, "headers": {}}
        if host_hdr:
            ws_settings["headers"]["Host"] = host_hdr
        elif sni:
            ws_settings["headers"]["Host"] = sni
        outbound["streamSettings"]["wsSettings"] = ws_settings
    elif net == "grpc":
        features.append("gRPC")
        outbound["streamSettings"]["grpcSettings"] = {
            "serviceName": service_name,
            "multiMode": mode == "multi",
        }
    elif net == "httpupgrade":
        features.append("HTTPUpgrade")
        outbound["streamSettings"]["httpupgradeSettings"] = {
            "path": path,
            "host": host_hdr or sni or server,
        }
    elif net == "h2":
        features.append("H2")
        outbound["streamSettings"]["httpSettings"] = {
            "path": path,
            "host": [host_hdr or sni or server],
        }

    return {
        "name": node_name,
        "raw_link": link,
        "port": port,
        "server": f"{server}:{server_port}",
        "network": net,
        "security": security,
        "features": features,
        "outbound": outbound,
    }


def build_xray_config(parsed_nodes):
    inbounds = []
    outbounds = []
    rules = []

    for node in parsed_nodes:
        port = node["port"]
        in_tag = f"in-{port}"
        out_tag = f"out-{port}"

        inbounds.append(
            {
                "tag": in_tag,
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }
        )
        outbounds.append(node["outbound"])
        rules.append(
            {
                "type": "field",
                "inboundTag": [in_tag],
                "outboundTag": out_tag,
            }
        )

    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules,
        },
    }


def generate_surge_snippets(nodes):
    if not nodes:
        return "", ""

    proxy_lines = ["[Proxy]"]
    node_names = []
    for node in nodes:
        name = node["name"]
        port = node["port"]
        proxy_lines.append(f"{name} = socks5, 127.0.0.1, {port}")
        node_names.append(name)

    proxy_snippet = "\n".join(proxy_lines)

    all_names_joined = ", ".join(node_names)
    group_lines = [
        "[Proxy Group]",
        f"VLESS 节点选择 = select, {all_names_joined}",
        f"VLESS 自动优选 = url-test, {all_names_joined}, url=http://cp.cloudflare.com/generate_204, interval=300, tolerance=50",
    ]
    group_snippet = "\n".join(group_lines)

    return proxy_snippet, group_snippet


def load_saved_nodes():
    if NODES_PATH.exists():
        try:
            return json.loads(NODES_PATH.read_text())
        except Exception:
            pass
    return {"raw": "", "nodes": []}


def save_nodes(raw_text, nodes):
    data = {"raw": raw_text, "nodes": nodes}
    NODES_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2))


class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/":
            index_path = TEMPLATES_DIR / "index.html"
            if index_path.exists():
                content = index_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                self.send_error(404, "Index template not found")
                return

        if path == "/api/status":
            saved = load_saved_nodes()
            nodes = saved.get("nodes", [])
            proxy_snippet, group_snippet = generate_surge_snippets(nodes)
            running = XrayManager.is_running()
            pid = XrayManager.get_pid()

            self.send_json(
                {
                    "ok": True,
                    "xray_installed": bool(XRAY_BIN),
                    "xray_bin": XRAY_BIN,
                    "running": running,
                    "pid": pid,
                    "nodes": nodes,
                    "raw": saved.get("raw", ""),
                    "surge_proxy": proxy_snippet,
                    "surge_group": group_snippet,
                }
            )
            return

        if path == "/api/ping":
            qs = urllib.parse.parse_qs(parsed_url.query)
            port_str = qs.get("port", [""])[0]
            if not port_str.isdigit():
                self.send_json({"ok": False, "error": "无效的端口号"}, 400)
                return

            port = int(port_str)
            # Run curl test
            try:
                t0 = time.time()
                res = subprocess.run(
                    [
                        "curl",
                        "-x",
                        f"socks5h://127.0.0.1:{port}",
                        "--connect-timeout",
                        "3",
                        "--max-time",
                        "4",
                        "-s",
                        "-w",
                        "%{http_code}:%{time_total}",
                        "-o",
                        "/dev/null",
                        "https://cp.cloudflare.com/generate_204",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                output = res.stdout.strip()
                if ":" in output:
                    code, total_time = output.split(":", 1)
                    if code in ("204", "200"):
                        ms = int(float(total_time) * 1000)
                        self.send_json({"ok": True, "latency": ms})
                        return
                self.send_json({"ok": False, "error": "节点超时或无法连通"})
            except Exception as e:
                self.send_json({"ok": False, "error": f"测速失败: {str(e)}"})
            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"

        try:
            body = json.loads(post_data) if post_data else {}
        except Exception:
            self.send_json({"ok": False, "error": "无效的 JSON 数据"}, 400)
            return

        if path == "/api/nodes":
            raw_text = body.get("raw_links", "")
            lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

            parsed_nodes = []
            seen_names = {}
            current_port = BASE_SOCKS_PORT

            for line in lines:
                if not line.startswith("vless://"):
                    continue
                node = parse_vless_link(line, current_port)
                if node:
                    # Deduplicate name
                    base_name = node["name"]
                    if base_name in seen_names:
                        seen_names[base_name] += 1
                        node["name"] = f"{base_name}_{seen_names[base_name]}"
                    else:
                        seen_names[base_name] = 1
                    parsed_nodes.append(node)
                    current_port += 1

            if not parsed_nodes:
                self.send_json(
                    {
                        "ok": False,
                        "error": "未解析到有效的 vless:// 链接，请检查输入格式",
                    },
                    400,
                )
                return

            # Build config
            config_dict = build_xray_config(parsed_nodes)

            # Test config using temporary file
            temp_config = DATA_DIR / "test_config.json"
            temp_config.write_text(json.dumps(config_dict, indent=2))
            try:
                XrayManager.test_config(temp_config)
            except Exception as e:
                temp_config.unlink(missing_ok=True)
                self.send_json({"ok": False, "error": str(e)}, 400)
                return
            finally:
                temp_config.unlink(missing_ok=True)

            # Save real config
            CONFIG_PATH.write_text(json.dumps(config_dict, indent=2))

            # Strip outbound detail from node display object
            display_nodes = []
            for n in parsed_nodes:
                dn = dict(n)
                dn.pop("outbound", None)
                display_nodes.append(dn)

            save_nodes(raw_text, display_nodes)

            # Restart Xray with new config
            try:
                XrayManager.start()
            except Exception as e:
                self.send_json(
                    {
                        "ok": False,
                        "error": f"配置已保存，但启动 Xray 失败: {str(e)}",
                    },
                    500,
                )
                return

            proxy_snippet, group_snippet = generate_surge_snippets(display_nodes)
            self.send_json(
                {
                    "ok": True,
                    "message": f"成功配置并启动 {len(display_nodes)} 个节点！",
                    "nodes": display_nodes,
                    "surge_proxy": proxy_snippet,
                    "surge_group": group_snippet,
                    "running": True,
                    "pid": XrayManager.get_pid(),
                }
            )
            return

        if path == "/api/restart":
            try:
                XrayManager.start()
                self.send_json({"ok": True, "pid": XrayManager.get_pid()})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 500)
            return

        if path == "/api/stop":
            XrayManager.stop()
            self.send_json({"ok": True, "running": False})
            return

        if path == "/api/start":
            try:
                XrayManager.start()
                self.send_json({"ok": True, "pid": XrayManager.get_pid()})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 500)
            return

        self.send_error(404, "Not Found")


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    # If config exists and wasn't running, start it
    if CONFIG_PATH.exists() and not XrayManager.is_running():
        try:
            XrayManager.start()
            print(f"[*] Xray 已在后台自启动 (PID: {XrayManager.get_pid()})")
        except Exception as e:
            print(f"[!] Xray 自启动失败: {e}")

    with ReusableTCPServer(("127.0.0.1", WEB_PORT), RequestHandler) as httpd:
        print(f"==================================================")
        print(f"🚀 Surge VLESS 桥接管理面板已启动!")
        print(f"👉 访问面板: http://127.0.0.1:{WEB_PORT}")
        print(f"⚙️ Xray 核心: {XRAY_BIN or '未找到(请先安装)'}")
        print(f"==================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n正在停止服务...")
        finally:
            httpd.server_close()


if __name__ == "__main__":
    main()
