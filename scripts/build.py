#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""多源订阅聚合 + 内核真连接实测 -> 只输出实测可用节点"""
import os
import re
import sys
import json
import time
import base64
import subprocess
import urllib.parse
import urllib.request
import concurrent.futures

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "output")
RT = os.path.join(ROOT, "runtime")
MIHOMO = os.path.join(RT, "mihomo")
CFG = os.path.join(RT, "config.yaml")
API = "http://127.0.0.1:19099"
PORT = 17890
SOCKS = 17891

TIMEOUT_MS = 5000
WORKERS = 24
ROUNDS = 2
MAX_OUT = 200
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"}

SOURCES = [
    "https://cdn.jsdelivr.net/gh/ermaozi/get_subscribe@main/subscribe/v2ray.txt",
    "https://cdn.jsdelivr.net/gh/ts-sf/fly@main/v2",
    "https://cdn.jsdelivr.net/gh/Pawdroid/Free-servers@main/sub",
    "https://cdn.jsdelivr.net/gh/ripaojiedian/freenode@main/sub",
    "https://cdn.jsdelivr.net/gh/freefq/free@master/v2",
]


def b64d(s):
    s = "".join(str(s).split()).replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    return urllib.request.urlopen(req, timeout=timeout).read()


def parse(uri):
    try:
        if uri.startswith("vmess://"):
            j = json.loads(b64d(uri[8:]))
            p = {"type": "vmess", "server": j["add"], "port": int(j["port"]), "uuid": j["id"],
                 "alterId": int(j.get("aid", 0) or 0), "cipher": j.get("scy") or "auto", "udp": True}
            net = j.get("net") or "tcp"
            if net == "ws":
                p["network"] = "ws"
                p["ws-opts"] = {"path": j.get("path") or "/", "headers": {"Host": j.get("host") or j["add"]}}
            elif net == "grpc":
                p["network"] = "grpc"
                p["grpc-opts"] = {"grpc-service-name": j.get("path") or ""}
            elif net != "tcp":
                return None
            if (j.get("tls") or "") in ("tls", "reality"):
                p["tls"] = True
                p["servername"] = j.get("sni") or j.get("host") or ""
                p["skip-cert-verify"] = True
            return p

        if uri.startswith("vless://"):
            u = urllib.parse.urlsplit(uri)
            q = dict(urllib.parse.parse_qsl(u.query))
            p = {"type": "vless", "server": u.hostname, "port": u.port, "uuid": u.username, "udp": True}
            if q.get("flow"):
                p["flow"] = q["flow"]
            sec = q.get("security") or "none"
            if sec in ("tls", "reality", "xtls"):
                p["tls"] = True
                p["servername"] = q.get("sni") or q.get("host") or u.hostname
                p["skip-cert-verify"] = True
                if sec == "reality" and q.get("pbk"):
                    p["reality-opts"] = {"public-key": q["pbk"]}
                    if q.get("sid"):
                        p["reality-opts"]["short-id"] = q["sid"]
                if q.get("fp"):
                    p["client-fingerprint"] = q["fp"]
            net = q.get("type") or "tcp"
            if net == "ws":
                p["network"] = "ws"
                p["ws-opts"] = {"path": q.get("path") or "/", "headers": {"Host": q.get("host") or p.get("servername") or ""}}
            elif net == "grpc":
                p["network"] = "grpc"
                p["grpc-opts"] = {"grpc-service-name": q.get("serviceName") or ""}
            elif net != "tcp":
                return None
            return p

        if uri.startswith("trojan://"):
            u = urllib.parse.urlsplit(uri)
            q = dict(urllib.parse.parse_qsl(u.query))
            p = {"type": "trojan", "server": u.hostname, "port": u.port,
                 "password": urllib.parse.unquote(u.username or ""), "udp": True, "skip-cert-verify": True}
            if q.get("sni"):
                p["sni"] = q["sni"]
            if q.get("type") == "ws":
                p["network"] = "ws"
                p["ws-opts"] = {"path": q.get("path") or "/", "headers": {"Host": q.get("host") or ""}}
            return p

        if uri.startswith("ss://"):
            body = uri[5:].split("#")[0]
            if "@" in body:
                head, hp = body.rsplit("@", 1)
                if ":" not in head:
                    head = b64d(head)
                hp = hp.split("/")[0].split("?")[0]
                host, port = hp.rsplit(":", 1)
                m, _, pw = head.partition(":")
            else:
                dec = b64d(body.split("?")[0])
                m_pw, hp = dec.rsplit("@", 1)
                m, _, pw = m_pw.partition(":")
                host, port = hp.rsplit(":", 1)
            return {"type": "ss", "server": host, "port": int(port), "cipher": m.strip(),
                    "password": pw, "udp": True}

        if uri.startswith(("hysteria2://", "hy2://")):
            u = urllib.parse.urlsplit(uri)
            q = dict(urllib.parse.parse_qsl(u.query))
            return {"type": "hysteria2", "server": u.hostname, "port": u.port,
                    "password": urllib.parse.unquote(u.username or ""),
                    "sni": q.get("sni") or "", "skip-cert-verify": True, "udp": True}

        if uri.startswith("tuic://"):
            u = urllib.parse.urlsplit(uri)
            return {"type": "tuic", "server": u.hostname, "port": u.port, "uuid": u.username,
                    "password": urllib.parse.unquote(u.password or ""), "skip-cert-verify": True, "udp": True}
    except Exception:
        return None
    return None


SS_CIPHERS = ("aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
              "xchacha20-ietf-poly1305", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
              "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "bf-cfb", "salsa20", "chacha20", "none")


def collect():
    urls = list(SOURCES)
    extra = os.environ.get("SUBS", "").strip()
    if extra:
        for line in re.split(r"[,\s]+", extra):
            if line.startswith("http"):
                urls.append(line)

    nodes, seen = [], set()
    for idx, url in enumerate(urls):
        try:
            raw = fetch(url)
            txt = raw.decode("utf-8", "ignore")
            if "://" not in txt[:500]:
                try:
                    txt = b64d(raw.decode("utf-8", "ignore"))
                except Exception:
                    pass
            cnt = 0
            for i, line in enumerate(txt.splitlines()):
                uri = line.strip()
                if "://" not in uri or uri.split("://")[0] not in ("vmess", "vless", "trojan", "ss", "hysteria2", "hy2", "tuic"):
                    continue
                p = parse(uri)
                if not p or not p.get("server") or not p.get("port"):
                    continue
                if p["type"] == "ss" and not str(p.get("cipher", "")).lower().startswith(SS_CIPHERS):
                    continue
                key = (p["server"], p["port"], p.get("uuid") or p.get("password"))
                if key in seen:
                    continue
                seen.add(key)
                p["name"] = "S%d-%04d" % (idx, i)
                nodes.append((p, uri))
                cnt += 1
            print("[source %d] %s -> %d" % (idx, url[:60], cnt), flush=True)
        except Exception as e:
            print("[source %d] FAIL %s: %s" % (idx, url[:60], e), flush=True)
    return nodes


def start_mihomo(nodes):
    os.makedirs(RT, exist_ok=True)
    cfg = {"port": PORT, "socks-port": SOCKS, "allow-lan": False, "mode": "global",
           "log-level": "silent", "external-controller": "127.0.0.1:19099",
           "proxies": [n[0] for n in nodes],
           "proxy-groups": [{"name": "G", "type": "select", "proxies": [n[0]["name"] for n in nodes]}],
           "rules": ["MATCH,G"]}
    with open(CFG, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
    os.chmod(MIHOMO, 0o755)
    p = subprocess.Popen([MIHOMO, "-d", RT, "-f", CFG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        time.sleep(1)
        try:
            urllib.request.urlopen(API + "/version", timeout=2).read()
            return p
        except Exception:
            if p.poll() is not None:
                break
    raise RuntimeError("mihomo start failed")


def delay(name):
    q = urllib.parse.urlencode({"url": "https://www.gstatic.com/generate_204", "timeout": str(TIMEOUT_MS)})
    try:
        r = json.load(urllib.request.urlopen("%s/proxies/%s/delay?%s" % (API, urllib.parse.quote(name, safe=""), q), timeout=12))
        return r.get("delay", -1) or -1
    except Exception:
        return -1


def main():
    nodes = collect()
    print("candidates:", len(nodes), flush=True)
    if not nodes:
        print("no candidate, abort")
        return 1

    proc = start_mihomo(nodes)
    passed = nodes
    last = {}
    try:
        for rnd in range(ROUNDS):
            t0 = time.time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
                res = dict(zip([n[0]["name"] for n in passed], ex.map(lambda n: delay(n[0]["name"]), passed)))
            last = res
            keep = [n for n in passed if res.get(n[0]["name"], -1) > 0]
            print("round %d: %d -> %d  (%.0fs)" % (rnd + 1, len(passed), len(keep), time.time() - t0), flush=True)
            passed = keep
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    final = [(last.get(p["name"], 9999) if last.get(p["name"], -1) > 0 else 9999, p, uri) for p, uri in passed]
    final.sort(key=lambda x: x[0])
    final = final[:MAX_OUT]

    os.makedirs(OUT, exist_ok=True)
    proxies = []
    for i, (d, p, uri) in enumerate(final, 1):
        q = dict(p)
        q["name"] = "N%03d-%dms" % (i, d)
        proxies.append(q)
    if proxies:
        clash = {"port": 7890, "socks-port": 7891, "allow-lan": False, "mode": "rule", "log-level": "warning",
                 "proxies": proxies,
                 "proxy-groups": [{"name": "PROXIES", "type": "select", "proxies": [p["name"] for p in proxies]},
                                  {"name": "AUTO", "type": "url-test", "url": "https://www.gstatic.com/generate_204",
                                   "interval": 300, "tolerance": 100, "proxies": [p["name"] for p in proxies]}],
                 "rules": ["MATCH,PROXIES"]}
    else:
        clash = {"port": 7890, "socks-port": 7891, "allow-lan": False, "mode": "rule", "log-level": "warning",
                 "proxies": [], "proxy-groups": [], "rules": ["MATCH,DIRECT"]}
    with open(os.path.join(OUT, "clash.yaml"), "w", encoding="utf-8") as f:
        yaml.safe_dump(clash, f, allow_unicode=True, sort_keys=False)

    raw_txt = "\n".join(u for _, _, u in final)
    with open(os.path.join(OUT, "v2ray.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode(raw_txt.encode("utf-8")).decode())

    with open(os.path.join(OUT, "stat.txt"), "w", encoding="utf-8") as f:
        f.write("candidates=%d\nalive=%d\nupdated=%s\n" % (len(nodes), len(final), time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())))

    print("output nodes:", len(final), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
