#!/usr/bin/env python3
"""
NKP Downloader backend — paste a signed Nutanix URL, it downloads onto
/data/nkp-sources with live progress. Static page + tiny JSON API.

Security:
- Only allows https://download.nutanix.com/... URLs (allowlist).
- Never passes the URL through a shell; uses requests with stream=True.
- Filename is derived from the URL path only (no traversal).
- Basic-auth gate (same creds as the file server).
"""
import os, re, threading, uuid, base64
from urllib.parse import urlparse, unquote
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import urllib.request, ssl

DEST = os.environ.get("NKP_DEST", "/data/nkp-sources")
PORT = int(os.environ.get("NKP_DL_PORT", "8445"))
USER = os.environ.get("NKP_DL_USER", "nkpfiles")
PASS = os.environ.get("NKP_DL_PASS", "changeme")
ALLOW_HOST = "download.nutanix.com"

# job registry: id -> {file, total, done, status, error}
JOBS = {}

def safe_name(url):
    path = urlparse(url).path
    name = unquote(path.rsplit("/", 1)[-1])
    # strip anything that isn't a sane filename char
    name = re.sub(r"[^A-Za-z0-9._-]", "", name)
    return name or "download.bin"

def allowed(url):
    try:
        u = urlparse(url)
        return u.scheme == "https" and u.hostname == ALLOW_HOST
    except Exception:
        return False

def download(job_id, url):
    job = JOBS[job_id]
    try:
        dest_path = os.path.join(DEST, job["file"])
        req = urllib.request.Request(url, headers={"User-Agent": "nkp-downloader"})
        with urllib.request.urlopen(req) as r:
            total = int(r.headers.get("Content-Length", 0))
            job["total"] = total
            with open(dest_path, "wb") as f:
                while True:
                    chunk = r.read(1024 * 256)
                    if not chunk:
                        break
                    f.write(chunk)
                    job["done"] += len(chunk)
        # best-effort SELinux relabel (ignored if not enforcing)
        os.system(f"restorecon -v {dest_path!r} 2>/dev/null || true")
        job["status"] = "done"
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)


# --- Prism Central v3 list helper ---
_SSL_NOVERIFY = ssl.create_default_context()
_SSL_NOVERIFY.check_hostname = False
_SSL_NOVERIFY.verify_mode = ssl.CERT_NONE

def pc_list(pc_ip, user, password, kind):
    """POST /api/nutanix/v3/{kind}s/list on Prism Central; return [{name,uuid},...]."""
    url = f"https://{pc_ip}:9440/api/nutanix/v3/{kind}s/list"
    body = json.dumps({"kind": kind, "length": 500}).encode()
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Basic " + auth,
    })
    with urllib.request.urlopen(req, timeout=20, context=_SSL_NOVERIFY) as r:
        data = json.loads(r.read())
    out = []
    for e in data.get("entities", []):
        meta = e.get("metadata", {})
        spec = e.get("spec", {})
        status = e.get("status", {})
        name = spec.get("name") or status.get("name") or "(unnamed)"
        uuid = meta.get("uuid", "")
        item = {"name": name, "uuid": uuid}
        # for subnets, include vlan + cluster if present
        if kind == "subnet":
            res = (status.get("resources") or {})
            item["vlan"] = res.get("vlan_id")
        if kind == "image":
            res = (status.get("resources") or {})
            item["type"] = res.get("image_type")
        out.append(item)
    # de-dup by name (PC can list image per-cluster copies)
    seen = {}
    for it in out:
        seen.setdefault(it["name"], it)
    return sorted(seen.values(), key=lambda x: x["name"].lower())

def pc_validate(host):
    # only allow plausible IPs / hostnames, no scheme, no path
    return bool(re.match(r'^[A-Za-z0-9.\-]{1,253}$', host or ""))

PAGE = None  # loaded from index file at startup

class H(BaseHTTPRequestHandler):
    def _auth_ok(self):
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Basic "):
            return False
        try:
            dec = base64.b64decode(hdr[6:]).decode()
            u, _, p = dec.partition(":")
            return u == USER and p == PASS
        except Exception:
            return False

    def _need_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="NKP Downloader"')
        self.end_headers()

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        if not self._auth_ok():
            return self._need_auth()
        if self.path in ("/", "/index.html"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/status/"):
            jid = self.path.rsplit("/", 1)[-1]
            job = JOBS.get(jid)
            if not job:
                self.send_response(404); self.end_headers(); return
            self._json(job)
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        # PC list endpoints authenticate against Prism Central itself (creds in body),
        # so they don't require the file-server basic-auth (allows the :8443 page to call them).
        if self.path in ("/pc/images", "/pc/subnets"):
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                return self._json({"error": "bad json"}, 400)
            pc = (data.get("pc") or "").strip()
            user = (data.get("user") or "").strip()
            pw = data.get("pass") or ""
            if not pc_validate(pc):
                return self._json({"error": "invalid PC address"}, 400)
            kind = "image" if self.path.endswith("images") else "subnet"
            try:
                items = pc_list(pc, user, pw, kind)
                return self._json({"items": items})
            except urllib.error.HTTPError as e:
                code = e.code
                msg = "auth failed (check user/password)" if code in (401,403) else f"PC returned HTTP {code}"
                return self._json({"error": msg}, 502)
            except Exception as e:
                return self._json({"error": f"could not reach PC: {e}"}, 502)
        if not self._auth_ok():
            return self._need_auth()
        if self.path != "/download":
            self.send_response(404); self.end_headers(); return
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"error": "bad json"}, 400)
        url = (data.get("url") or "").strip()
        if not allowed(url):
            return self._json({"error": "only https://download.nutanix.com/ URLs are allowed"}, 400)
        jid = uuid.uuid4().hex[:12]
        JOBS[jid] = {"file": safe_name(url), "total": 0, "done": 0, "status": "running", "error": ""}
        threading.Thread(target=download, args=(jid, url), daemon=True).start()
        self._json({"job": jid, "file": JOBS[jid]["file"]})

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

def main():
    global PAGE
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "page.html")) as f:
        PAGE = f.read()
    os.makedirs(DEST, exist_ok=True)
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    cert = os.environ.get("NKP_TLS_CERT", "")
    key = os.environ.get("NKP_TLS_KEY", "")
    if cert and key and os.path.exists(cert) and os.path.exists(key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"NKP downloader backend on https://0.0.0.0:{PORT}  dest={DEST}")
    else:
        print(f"NKP downloader backend on http://0.0.0.0:{PORT}  dest={DEST}  (no TLS cert; set NKP_TLS_CERT/KEY)")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
