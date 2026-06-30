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
import os, re, threading, uuid, base64, time
from urllib.parse import urlparse, unquote
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import urllib.request, urllib.error, ssl

DEST = os.environ.get("NKP_DEST", "/data/nkp-sources")
PORT = int(os.environ.get("NKP_DL_PORT", "8445"))
USER = os.environ.get("NKP_DL_USER", "nkpfiles")
PASS = os.environ.get("NKP_DL_PASS", "changeme")
ALLOW_HOST = "download.nutanix.com"

# job registry: id -> {file, version, dest, total, done, status, error, queued, started, ended}
#   status: queued | running | done | error | canceled
JOBS = {}
QUEUE = []                      # list of job_ids waiting to run, in order
QLOCK = threading.Lock()        # guards JOBS + QUEUE
_WORKER_STARTED = False

def safe_name(url):
    path = urlparse(url).path
    name = unquote(path.rsplit("/", 1)[-1])
    name = re.sub(r"[^A-Za-z0-9._-]", "", name)
    return name or "download.bin"

def allowed(url):
    try:
        u = urlparse(url)
        return u.scheme == "https" and u.hostname == ALLOW_HOST
    except Exception:
        return False

def version_dest(version):
    """Resolve (and create) the destination folder for a given NKP version.
       version '' or None -> the base DEST. '2.17.1' -> DEST/nkp-v2.17.1/."""
    if not version:
        d = DEST
    else:
        v = re.sub(r"[^0-9.]", "", str(version))     # sanitize: digits + dots only
        d = os.path.join(DEST, f"nkp-v{v}") if v else DEST
    os.makedirs(d, exist_ok=True)                     # auto-create if missing
    os.system(f"restorecon -d {d!r} 2>/dev/null || true")
    return d

def download(job_id):
    job = JOBS[job_id]
    url = job["url"]
    try:
        job["status"] = "running"
        job["started"] = time.time()
        dest_dir = version_dest(job.get("version"))
        job["dest"] = dest_dir
        dest_path = os.path.join(dest_dir, job["file"])
        req = urllib.request.Request(url, headers={"User-Agent": "nkp-downloader"})
        with urllib.request.urlopen(req) as r:
            job["total"] = int(r.headers.get("Content-Length", 0))
            with open(dest_path, "wb") as f:
                while True:
                    if job.get("cancel"):
                        raise RuntimeError("canceled by user")
                    chunk = r.read(1024 * 256)
                    if not chunk:
                        break
                    f.write(chunk)
                    job["done"] += len(chunk)
        os.system(f"restorecon -v {dest_path!r} 2>/dev/null || true")
        job["status"] = "done"
        job["path"] = dest_path
    except Exception as e:
        job["status"] = "canceled" if job.get("cancel") else "error"
        job["error"] = "" if job.get("cancel") else str(e)
    finally:
        job["ended"] = time.time()

def _worker():
    """Single sequential worker: pulls one job at a time off QUEUE and runs it."""
    while True:
        jid = None
        with QLOCK:
            if QUEUE:
                jid = QUEUE.pop(0)
        if jid is None:
            time.sleep(0.4)
            continue
        job = JOBS.get(jid)
        if not job or job.get("cancel"):
            if job and job.get("cancel"):
                job["status"] = "canceled"; job["ended"] = time.time()
            continue
        download(jid)            # blocks until this one finishes, then loops

def ensure_worker():
    global _WORKER_STARTED
    if not _WORKER_STARTED:
        _WORKER_STARTED = True
        threading.Thread(target=_worker, daemon=True).start()

def enqueue(url, version):
    jid = uuid.uuid4().hex[:12]
    JOBS[jid] = {
        "job": jid, "url": url, "file": safe_name(url), "version": version or "",
        "dest": "", "total": 0, "done": 0, "status": "queued", "error": "",
        "queued": time.time(), "started": 0, "ended": 0, "cancel": False,
    }
    with QLOCK:
        QUEUE.append(jid)
    ensure_worker()
    return jid

def queue_position(jid):
    with QLOCK:
        return QUEUE.index(jid) + 1 if jid in QUEUE else 0


# --- Prism Central v4 list helper (namespace-aware) ---
_SSL_NOVERIFY = ssl.create_default_context()
_SSL_NOVERIFY.check_hostname = False
_SSL_NOVERIFY.verify_mode = ssl.CERT_NONE

# v4 endpoint map: kind -> (namespace, version, path).
# Versions are the GA-era defaults; we fall back across a few minor versions if PC is older/newer.
_V4_MAP = {
    "cluster": ("clustermgmt", ["v4.0", "v4.1"], "config/clusters"),
    "subnet":  ("networking",  ["v4.0", "v4.1"], "config/subnets"),
    "image":   ("vmm",         ["v4.0", "v4.1", "v4.2"], "content/images"),
}

def _http_get_json(url, user, password, timeout=20):
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(url, method="GET", headers={
        "Accept": "application/json",
        "Authorization": "Basic " + auth,
    })
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_NOVERIFY) as r:
        return json.loads(r.read())

def pc_list(pc_ip, user, password, kind):
    """v4 GET on the right namespace; return [{name,uuid,...}]. Falls back across versions."""
    ns, versions, path = _V4_MAP[kind]
    data, last_err = None, None
    for ver in versions:
        url = f"https://{pc_ip}:9440/api/{ns}/{ver}/{path}?$page=0&$limit=100"
        try:
            data = _http_get_json(url, user, password)
            break
        except urllib.error.HTTPError as e:
            last_err = e
            # 404/406 => that version/namespace not present; try next
            if e.code in (404, 406):
                continue
            raise
    if data is None:
        raise last_err or RuntimeError("no v4 version responded")

    entities = data.get("data") or []   # v4 wraps results in "data"
    out = []
    for e in entities:
        name = e.get("name") or "(unnamed)"
        uuid = e.get("extId") or e.get("ext_id") or ""
        item = {"name": name, "uuid": uuid}
        if kind == "subnet":
            item["vlan"] = e.get("networkId") if "networkId" in e else e.get("vlanId")
            item["cluster_uuid"] = e.get("clusterReference") or ""
        if kind == "image":
            item["type"] = e.get("type") or ""
            # v4 images carry their cluster placement here -> enables per-cluster filtering
            item["cluster_uuids"] = e.get("clusterLocationExtIds") or []
        if kind == "cluster":
            # a real PE cluster has the AOS/hypervisor config; the PC itself is type PRISM_CENTRAL
            cfg = (e.get("config") or {})
            ctype = (cfg.get("clusterFunction") or cfg.get("clusterFunctions") or [])
            if isinstance(ctype, str): ctype = [ctype]
            item["is_pe"] = ("PRISM_CENTRAL" not in ctype)
        out.append(item)
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
            out = dict(job); out["queue_pos"] = queue_position(jid)
            self._json(out)
        elif self.path == "/jobs":
            # all jobs, queue first (by queue order) then running/recent by time
            out = []
            for jid, j in JOBS.items():
                e = dict(j); e["queue_pos"] = queue_position(jid); out.append(e)
            # sort: running first, then queued by position, then finished by ended desc
            rank = {"running": 0, "queued": 1, "done": 2, "error": 2, "canceled": 2}
            out.sort(key=lambda e: (rank.get(e["status"], 3),
                                    e["queue_pos"] or 0,
                                    -(e.get("ended") or e.get("queued") or 0)))
            self._json({"jobs": out})
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        # PC list endpoints authenticate against Prism Central itself (creds in body),
        # so they don't require the file-server basic-auth (allows the :8443 page to call them).
        if self.path in ("/pc/images", "/pc/subnets", "/pc/clusters"):
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
            if self.path.endswith("images"):
                kind = "image"
            elif self.path.endswith("subnets"):
                kind = "subnet"
            else:
                kind = "cluster"
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
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"error": "bad json"}, 400)

        if self.path == "/download":
            url = (data.get("url") or "").strip()
            version = (data.get("version") or "").strip()
            if not allowed(url):
                return self._json({"error": "only https://download.nutanix.com/ URLs are allowed"}, 400)
            jid = enqueue(url, version)
            j = JOBS[jid]
            return self._json({"job": jid, "file": j["file"], "version": version,
                               "queue_pos": queue_position(jid)})

        if self.path == "/cancel":
            jid = (data.get("job") or "").strip()
            job = JOBS.get(jid)
            if not job:
                return self._json({"error": "no such job"}, 404)
            job["cancel"] = True
            with QLOCK:
                if jid in QUEUE:           # not started yet -> drop from queue immediately
                    QUEUE.remove(jid); job["status"] = "canceled"; job["ended"] = time.time()
            return self._json({"job": jid, "status": job["status"]})

        if self.path == "/clear":
            # remove finished/canceled/errored jobs from the list (does not touch files)
            drop = [jid for jid, j in JOBS.items() if j["status"] in ("done", "error", "canceled")]
            for jid in drop:
                JOBS.pop(jid, None)
            return self._json({"cleared": len(drop)})

        self.send_response(404); self.end_headers()

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
