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
LOG_PATH = DATA_DIR / "core.log"
PID_PATH = DATA_DIR / "core.pid"
LEGACY_PID_PATH = DATA_DIR / "xray.pid"

BASE_SOCKS_PORT = 10810
WEB_PORT = 9099


def find_binary(name: str):
    candidates = [
        shutil.which(name),
        f"/opt/homebrew/bin/{name}",
        f"/usr/local/bin/{name}",
        os.path.expanduser(f"~/.local/bin/{name}"),
        f"/usr/bin/{name}",
        str(BASE_DIR / name),
    ]
    for c in candidates:
        if c and os.path.exists(c) and os.access(c, os.X_OK):
            return c
    return None


SING_BOX_BIN = find_binary("sing-box")
XRAY_BIN = find_binary("xray")


class CoreManager:
    process = None
    active_core_type = None  # "sing-box" or "xray"

    @classmethod
    def get_pid(cls):
        if cls.process and cls.process.poll() is None:
            return cls.process.pid
        for p_file in [PID_PATH, LEGACY_PID_PATH]:
            if p_file.exists():
                try:
                    pid = int(p_file.read_text().strip())
                    os.kill(pid, 0)
                    return pid
                except (ValueError, OSError):
                    p_file.unlink(missing_ok=True)
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
        cls.active_core_type = None
        PID_PATH.unlink(missing_ok=True)
        LEGACY_PID_PATH.unlink(missing_ok=True)

    @classmethod
    def start(cls, core_type=None, bin_path=None):
        cls.stop()
        if not CONFIG_PATH.exists():
            return False

        if not core_type or not bin_path:
            # Detect from existing config or defaults
            try:
                cfg = json.loads(CONFIG_PATH.read_text())
                if "route" in cfg:
                    core_type = "sing-box"
                    bin_path = find_binary("sing-box")
                else:
                    core_type = "xray"
                    bin_path = find_binary("xray")
            except Exception:
                core_type = "sing-box" if find_binary("sing-box") else "xray"
                bin_path = find_binary(core_type)

        if not bin_path:
            raise RuntimeError(f"未在系统中找到 {core_type} 可执行文件，请先安装: brew install {core_type}")

        log_file = open(LOG_PATH, "a")
        proc = subprocess.Popen(
            [bin_path, "run", "-c", str(CONFIG_PATH)],
            stdout=log_file,
            stderr=log_file,
            start_new_session=True,
        )
        cls.process = proc
        cls.active_core_type = core_type
        PID_PATH.write_text(str(proc.pid))
        time.sleep(0.4)
        if proc.poll() is not None:
            PID_PATH.unlink(missing_ok=True)
            raise RuntimeError(f"{core_type} 启动失败，请检查配置文件或端口是否被占用")
        return True

    @classmethod
    def test_config(cls, core_type: str, bin_path: str, test_config_path: Path):
        if core_type == "sing-box":
            cmd = [bin_path, "check", "-c", str(test_config_path)]
        else:
            cmd = [bin_path, "run", "-test", "-c", str(test_config_path)]

        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            err_msg = res.stdout.strip() or res.stderr.strip()
            err_msg = re.sub(r"/[^\s]+/(test_config\.json|config\.json|tmp_[^\s]+)", r"[\1]", err_msg)
            err_msg = re.sub(r"/var/folders/[^\s]+", "[tmp_config]", err_msg)
            raise RuntimeError(f"{core_type} 配置校验失败:\n{err_msg}")
        return True


def sanitize_surge_name(name: str) -> str:
    cleaned = re.sub(r"[,=\r\n]", "_", name.strip())
    return cleaned if cleaned else "Proxy_Node"


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

    features = []
    if security == "reality":
        features.append("Reality")
    elif security == "tls":
        features.append("TLS")

    if flow:
        features.append(flow)

    if net == "ws":
        features.append("WS")
    elif net == "grpc":
        features.append("gRPC")
    elif net == "httpupgrade":
        features.append("HTTPUpgrade")
    elif net == "h2":
        features.append("H2")

    return {
        "protocol": "vless",
        "name": node_name,
        "raw_link": link,
        "port": port,
        "server": f"{server}:{server_port}",
        "server_host": server,
        "server_port": server_port,
        "uuid": uuid,
        "sni": sni,
        "pbk": pbk,
        "sid": sid,
        "spx": spx,
        "flow": flow,
        "path": path,
        "host_hdr": host_hdr,
        "service_name": service_name,
        "network": net,
        "security": security,
        "features": features,
        "fp": fp,
        "alpn": alpn,
        "encryption": encryption,
    }


def parse_anytls_link(link: str, port: int):
    link = link.strip()
    if not link.startswith("anytls://"):
        return None

    try:
        p = urllib.parse.urlsplit(link)
    except Exception:
        return None

    if p.scheme != "anytls":
        return None

    password = p.password or p.username or ""
    server = p.hostname or ""
    server_port = p.port or 443

    if not password or not server:
        return None

    qs = urllib.parse.parse_qs(p.query)

    def q(k, default=""):
        val = qs.get(k)
        return val[0].strip() if val else default

    sni = q("sni", q("serverName", q("peer", server)))
    insecure = q("insecure", q("allowInsecure", "0")).lower() in ("1", "true", "yes")
    alpn_str = q("alpn", "")
    fp = q("fp", q("fingerprint", "chrome"))

    raw_remark = urllib.parse.unquote(p.fragment).strip() if p.fragment else ""
    node_name = sanitize_surge_name(raw_remark or f"AnyTLS_{server}_{port}")

    features = ["AnyTLS"]
    if insecure:
        features.append("Insecure")
    if alpn_str:
        features.append(alpn_str)

    return {
        "protocol": "anytls",
        "name": node_name,
        "raw_link": link,
        "port": port,
        "server": f"{server}:{server_port}",
        "server_host": server,
        "server_port": server_port,
        "password": password,
        "sni": sni,
        "insecure": insecure,
        "alpn": alpn_str,
        "fp": fp,
        "features": features,
    }


def parse_node_link(link: str, port: int):
    link = link.strip()
    if link.startswith("vless://"):
        return parse_vless_link(link, port)
    elif link.startswith("anytls://"):
        return parse_anytls_link(link, port)
    return None


def build_singbox_vless_outbound(node: dict) -> dict:
    port = node["port"]
    server = node["server_host"]
    server_port = node["server_port"]
    uuid = node["uuid"]
    flow = node.get("flow", "")
    security = node.get("security", "none")
    net = node.get("network", "tcp")
    sni = node.get("sni", "")
    fp = node.get("fp", "chrome") or "chrome"
    pbk = node.get("pbk", "")
    sid = node.get("sid", "")
    path = node.get("path", "/")
    host_hdr = node.get("host_hdr", "")
    service_name = node.get("service_name", "")

    outbound = {
        "type": "vless",
        "tag": f"out-{port}",
        "server": server,
        "server_port": server_port,
        "uuid": uuid,
        "packet_encoding": "xudp",
    }
    if flow:
        outbound["flow"] = flow

    if security == "reality":
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni or server,
            "reality": {
                "enabled": True,
                "public_key": pbk,
                "short_id": sid or "",
            },
            "utls": {
                "enabled": True,
                "fingerprint": fp,
            },
        }
    elif security == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni or server,
            "insecure": False,
            "utls": {
                "enabled": True,
                "fingerprint": fp,
            },
        }
        if node.get("alpn"):
            outbound["tls"]["alpn"] = [x.strip() for x in node["alpn"].split(",") if x.strip()]

    if net == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": path,
            "headers": {"Host": host_hdr or sni or server} if (host_hdr or sni or server) else {},
        }
    elif net == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": service_name,
        }
    elif net == "httpupgrade":
        outbound["transport"] = {
            "type": "httpupgrade",
            "path": path,
            "host": host_hdr or sni or server,
        }
    elif net == "h2":
        outbound["transport"] = {
            "type": "http",
            "path": path,
            "host": [host_hdr or sni or server],
        }

    return outbound


def build_singbox_anytls_outbound(node: dict) -> dict:
    port = node["port"]
    server = node["server_host"]
    server_port = node["server_port"]
    password = node.get("password", "")
    sni = node.get("sni", "") or server
    insecure = bool(node.get("insecure", False))
    alpn_str = node.get("alpn", "")
    alpn = [x.strip() for x in alpn_str.split(",") if x.strip()] if alpn_str else []
    fp = node.get("fp", "chrome") or "chrome"

    tls_cfg = {
        "enabled": True,
        "server_name": sni,
        "insecure": insecure,
        "utls": {
            "enabled": True,
            "fingerprint": fp,
        },
    }
    if alpn:
        tls_cfg["alpn"] = alpn

    return {
        "type": "anytls",
        "tag": f"out-{port}",
        "server": server,
        "server_port": server_port,
        "password": password,
        "tls": tls_cfg,
    }


def build_singbox_config(parsed_nodes):
    inbounds = []
    outbounds = []
    rules = []

    for node in parsed_nodes:
        port = node["port"]
        in_tag = f"in-{port}"
        out_tag = f"out-{port}"

        inbounds.append(
            {
                "type": "socks",
                "tag": in_tag,
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        )

        if node.get("protocol") == "anytls":
            outbound = build_singbox_anytls_outbound(node)
        else:
            outbound = build_singbox_vless_outbound(node)

        outbounds.append(outbound)
        rules.append(
            {
                "inbound": in_tag,
                "outbound": out_tag,
            }
        )

    outbounds.append({"type": "direct", "tag": "direct"})
    outbounds.append({"type": "block", "tag": "block"})

    return {
        "log": {"level": "warn"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": rules,
        },
    }


def build_xray_vless_outbound(node: dict) -> dict:
    port = node["port"]
    server = node["server_host"]
    server_port = node["server_port"]
    uuid = node["uuid"]
    flow = node.get("flow", "")
    security = node.get("security", "none")
    net = node.get("network", "tcp")
    sni = node.get("sni", "")
    fp = node.get("fp", "chrome") or "chrome"
    pbk = node.get("pbk", "")
    sid = node.get("sid", "")
    spx = node.get("spx", "")
    path = node.get("path", "/")
    host_hdr = node.get("host_hdr", "")
    service_name = node.get("service_name", "")
    alpn = node.get("alpn", "")
    encryption = node.get("encryption", "none")

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

    if security == "reality":
        outbound["streamSettings"]["realitySettings"] = {
            "show": False,
            "fingerprint": fp or "chrome",
            "serverName": sni or server,
            "publicKey": pbk,
            "shortId": sid or "",
            "spiderX": spx or "",
        }
    elif security == "tls":
        tls_settings = {
            "serverName": sni or server,
            "fingerprint": fp or "chrome",
            "allowInsecure": False,
        }
        if alpn:
            tls_settings["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        outbound["streamSettings"]["tlsSettings"] = tls_settings

    if net == "ws":
        ws_settings = {"path": path, "headers": {}}
        if host_hdr:
            ws_settings["headers"]["Host"] = host_hdr
        elif sni:
            ws_settings["headers"]["Host"] = sni
        outbound["streamSettings"]["wsSettings"] = ws_settings
    elif net == "grpc":
        outbound["streamSettings"]["grpcSettings"] = {
            "serviceName": service_name,
            "multiMode": False,
        }
    elif net == "httpupgrade":
        outbound["streamSettings"]["httpupgradeSettings"] = {
            "path": path,
            "host": host_hdr or sni or server,
        }
    elif net == "h2":
        outbound["streamSettings"]["httpSettings"] = {
            "path": path,
            "host": [host_hdr or sni or server],
        }

    return outbound


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
        outbounds.append(build_xray_vless_outbound(node))
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


def get_best_core(nodes):
    has_anytls = any(n.get("protocol") == "anytls" or n.get("raw_link", "").startswith("anytls://") for n in nodes)
    singbox_bin = find_binary("sing-box")
    xray_bin = find_binary("xray")

    if has_anytls:
        if not singbox_bin:
            raise RuntimeError("检测到 AnyTLS 协议节点，该协议需要 sing-box 内核支持。\n请在终端运行: brew install sing-box")
        return "sing-box", singbox_bin

    if singbox_bin:
        return "sing-box", singbox_bin
    elif xray_bin:
        return "xray", xray_bin
    else:
        raise RuntimeError("未在系统中找到 sing-box 或 xray 内核，请先安装:\nbrew install sing-box")


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
        f"节点选择 = select, {all_names_joined}",
        f"自动优选 = url-test, {all_names_joined}, url=http://cp.cloudflare.com/generate_204, interval=300, tolerance=50",
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


def rebuild_and_apply_nodes(node_list):
    """
    Rebuilds complete configuration from given node dicts, validates, saves, and restarts core.
    """
    if not node_list:
        save_nodes("", [])
        CoreManager.stop()
        CONFIG_PATH.unlink(missing_ok=True)
        return True, []

    full_nodes = []
    seen_names = {}
    for n in node_list:
        port = n["port"]
        raw = n.get("raw_link", "").strip()
        parsed = parse_node_link(raw, port)
        if parsed:
            desired_name = n.get("name") or parsed["name"]
            if desired_name in seen_names:
                seen_names[desired_name] += 1
                desired_name = f"{desired_name}_{seen_names[desired_name]}"
            else:
                seen_names[desired_name] = 1
            parsed["name"] = desired_name
            full_nodes.append(parsed)

    if not full_nodes:
        raise RuntimeError("所有节点均解析失败，请检查链接有效性")

    core_type, bin_path = get_best_core(full_nodes)

    if core_type == "sing-box":
        config_dict = build_singbox_config(full_nodes)
    else:
        config_dict = build_xray_config(full_nodes)

    temp_config = DATA_DIR / "test_config.json"
    temp_config.write_text(json.dumps(config_dict, indent=2))
    try:
        CoreManager.test_config(core_type, bin_path, temp_config)
    except Exception as e:
        temp_config.unlink(missing_ok=True)
        raise e
    finally:
        temp_config.unlink(missing_ok=True)

    CONFIG_PATH.write_text(json.dumps(config_dict, indent=2))

    display_nodes = []
    raw_links = []
    for n in full_nodes:
        dn = dict(n)
        display_nodes.append(dn)
        raw_links.append(n["raw_link"])

    save_nodes("\n".join(raw_links), display_nodes)
    CoreManager.start(core_type, bin_path)
    return True, display_nodes


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
            running = CoreManager.is_running()
            pid = CoreManager.get_pid()

            core_type = CoreManager.active_core_type
            if not core_type:
                core_type = "sing-box" if SING_BOX_BIN else ("xray" if XRAY_BIN else None)

            self.send_json(
                {
                    "ok": True,
                    "core_installed": bool(SING_BOX_BIN or XRAY_BIN),
                    "core_type": core_type or "sing-box",
                    "sing_box_installed": bool(SING_BOX_BIN),
                    "xray_installed": bool(XRAY_BIN),
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
            try:
                clean_env = os.environ.copy()
                for k in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
                    clean_env.pop(k, None)

                res = subprocess.run(
                    [
                        "curl",
                        "-x",
                        f"socks5h://127.0.0.1:{port}",
                        "--connect-timeout",
                        "4",
                        "--max-time",
                        "5",
                        "-s",
                        "-w",
                        "%{http_code}:%{time_total}",
                        "-o",
                        "/dev/null",
                        "https://cp.cloudflare.com/generate_204",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=6,
                    env=clean_env,
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
            mode = body.get("mode", "append")  # "append" or "replace"
            raw_text = body.get("raw_links", "")
            lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

            saved = load_saved_nodes()
            existing_nodes = saved.get("nodes", []) if mode == "append" else []
            existing_links = set(n.get("raw_link", "").strip() for n in existing_nodes)
            existing_ports = set(n["port"] for n in existing_nodes if "port" in n)

            # Monotonic sequential port allocation
            if existing_ports:
                next_port = max(existing_ports) + 1
            else:
                next_port = BASE_SOCKS_PORT

            added_count = 0
            skipped_count = 0
            new_nodes_to_add = []

            for line in lines:
                if not (line.startswith("vless://") or line.startswith("anytls://")):
                    continue
                if line in existing_links:
                    skipped_count += 1
                    continue

                while next_port in existing_ports:
                    next_port += 1

                temp_node = parse_node_link(line, next_port)
                if temp_node:
                    new_nodes_to_add.append(temp_node)
                    existing_links.add(line)
                    existing_ports.add(next_port)
                    next_port += 1
                    added_count += 1

            if added_count == 0:
                if skipped_count > 0:
                    self.send_json(
                        {"ok": False, "error": f"所粘贴的 {skipped_count} 个节点已存在，未重复添加"},
                        400,
                    )
                else:
                    self.send_json(
                        {"ok": False, "error": "未解析到有效的 vless:// 或 anytls:// 链接，请检查输入格式"},
                        400,
                    )
                return

            combined_nodes = list(existing_nodes) + new_nodes_to_add
            try:
                _, display_nodes = rebuild_and_apply_nodes(combined_nodes)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 400)
                return

            proxy_snippet, group_snippet = generate_surge_snippets(display_nodes)
            msg = f"成功追加 {added_count} 个节点！" if mode == "append" else f"已覆盖保存 {added_count} 个节点！"
            if skipped_count > 0:
                msg += f"（已自动跳过 {skipped_count} 个重复节点）"

            self.send_json(
                {
                    "ok": True,
                    "message": msg,
                    "added_count": added_count,
                    "skipped_count": skipped_count,
                    "nodes": display_nodes,
                    "surge_proxy": proxy_snippet,
                    "surge_group": group_snippet,
                    "running": True,
                    "pid": CoreManager.get_pid(),
                }
            )
            return

        if path == "/api/nodes/delete":
            port_to_delete = body.get("port")
            if not port_to_delete:
                self.send_json({"ok": False, "error": "缺少要删除的节点端口"}, 400)
                return

            saved = load_saved_nodes()
            existing_nodes = saved.get("nodes", [])
            remaining_nodes = [n for n in existing_nodes if n.get("port") != port_to_delete]

            if len(remaining_nodes) == len(existing_nodes):
                self.send_json({"ok": False, "error": "未找到该节点"}, 404)
                return

            try:
                _, display_nodes = rebuild_and_apply_nodes(remaining_nodes)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 500)
                return

            proxy_snippet, group_snippet = generate_surge_snippets(display_nodes)
            self.send_json(
                {
                    "ok": True,
                    "message": "节点已删除！",
                    "nodes": display_nodes,
                    "surge_proxy": proxy_snippet,
                    "surge_group": group_snippet,
                    "running": CoreManager.is_running(),
                    "pid": CoreManager.get_pid(),
                }
            )
            return

        if path == "/api/nodes/update":
            original_port = body.get("original_port")
            new_port = body.get("port") or original_port
            raw_link = body.get("raw_link", "").strip()
            name = body.get("name", "").strip()

            if not original_port:
                self.send_json({"ok": False, "error": "缺少原节点端口标识"}, 400)
                return

            if not raw_link:
                self.send_json({"ok": False, "error": "节点链接不能为空"}, 400)
                return

            try:
                original_port = int(original_port)
                new_port = int(new_port)
            except ValueError:
                self.send_json({"ok": False, "error": "端口号必须为数字"}, 400)
                return

            saved = load_saved_nodes()
            existing_nodes = saved.get("nodes", [])

            target_idx = -1
            for i, n in enumerate(existing_nodes):
                if n.get("port") == original_port:
                    target_idx = i
                    break

            if target_idx == -1:
                self.send_json({"ok": False, "error": "未找到要修改的节点"}, 404)
                return

            # Check port conflict if port changed
            if new_port != original_port:
                for i, n in enumerate(existing_nodes):
                    if i != target_idx and n.get("port") == new_port:
                        self.send_json(
                            {
                                "ok": False,
                                "error": f"端口 {new_port} 已被节点【{n.get('name')}】占用，请更换端口",
                            },
                            400,
                        )
                        return

            parsed = parse_node_link(raw_link, new_port)
            if not parsed:
                self.send_json(
                    {
                        "ok": False,
                        "error": "修改后的链接解析失败，请检查 vless:// 或 anytls:// 链接格式是否正确",
                    },
                    400,
                )
                return

            if name:
                parsed["name"] = sanitize_surge_name(name)

            updated_nodes = list(existing_nodes)
            updated_node_dict = dict(parsed)
            updated_nodes[target_idx] = updated_node_dict

            try:
                _, display_nodes = rebuild_and_apply_nodes(updated_nodes)
            except Exception as e:
                self.send_json(
                    {"ok": False, "error": f"配置校验或启动失败: {str(e)}"}, 400
                )
                return

            proxy_snippet, group_snippet = generate_surge_snippets(display_nodes)
            self.send_json(
                {
                    "ok": True,
                    "message": f"节点【{parsed['name']}】修改成功并已生效！",
                    "nodes": display_nodes,
                    "surge_proxy": proxy_snippet,
                    "surge_group": group_snippet,
                    "running": CoreManager.is_running(),
                    "pid": CoreManager.get_pid(),
                }
            )
            return

        if path == "/api/nodes/clear":
            try:
                rebuild_and_apply_nodes([])
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 500)
                return

            self.send_json(
                {
                    "ok": True,
                    "message": "已清空所有节点并停止内核",
                    "nodes": [],
                    "surge_proxy": "",
                    "surge_group": "",
                    "running": False,
                    "pid": None,
                }
            )
            return

        if path == "/api/restart":
            try:
                saved = load_saved_nodes()
                nodes = saved.get("nodes", [])
                if nodes:
                    rebuild_and_apply_nodes(nodes)
                else:
                    CoreManager.start()
                self.send_json({"ok": True, "pid": CoreManager.get_pid()})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 500)
            return

        if path == "/api/stop":
            CoreManager.stop()
            self.send_json({"ok": True, "running": False})
            return

        if path == "/api/start":
            try:
                saved = load_saved_nodes()
                nodes = saved.get("nodes", [])
                if nodes:
                    rebuild_and_apply_nodes(nodes)
                else:
                    CoreManager.start()
                self.send_json({"ok": True, "pid": CoreManager.get_pid()})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 500)
            return

        self.send_error(404, "Not Found")


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    saved = load_saved_nodes()
    nodes = saved.get("nodes", [])

    if nodes and not CoreManager.is_running():
        try:
            rebuild_and_apply_nodes(nodes)
            print(f"[*] 代理内核已在后台自启动 (PID: {CoreManager.get_pid()}, 核心: {CoreManager.active_core_type})")
        except Exception as e:
            print(f"[!] 代理内核自启动失败: {e}")

    with ReusableTCPServer(("127.0.0.1", WEB_PORT), RequestHandler) as httpd:
        core_info = "sing-box / xray" if (SING_BOX_BIN and XRAY_BIN) else (SING_BOX_BIN or XRAY_BIN or "未找到(请先安装)")
        print(f"==================================================")
        print(f"🚀 Surge VLESS & AnyTLS 桥接管理中枢已启动!")
        print(f"👉 访问面板: http://127.0.0.1:{WEB_PORT}")
        print(f"⚙️ 代理内核: {core_info}")
        print(f"==================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n正在停止服务...")
        finally:
            httpd.server_close()


if __name__ == "__main__":
    main()
