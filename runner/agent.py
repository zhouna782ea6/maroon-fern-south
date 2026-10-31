"""临时测试代理：控制租约失效时立即关闭数据通道。"""
import hashlib
import json
import os
import pathlib
import signal
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from probes import check

GOST_VERSION = "3.3.2"
GOST_SHA = "162feb43b1c284dbea599cdfe898169931af875233060dedc19432c7a9d18274"
TAILSCALE_VERSION = "1.104.4"
TAILSCALE_SHA = "624ea093d47d62cf56f17b8332d74b8decda4a1faa610ebc60a1de334b2b3dc9"
MAX_DOWNLOAD = 256 * 1024 * 1024
HTTP_TIMEOUT = 30
LOG_TIMEOUT = 2
LOG_LIMIT = 24
LOG_LINES = []
BOOTSTRAP_RETRIES = 3
CONTROL = os.environ["TSM_CONTROL_URL"].rstrip("/")
ATTEMPT = os.environ["TSM_ATTEMPT"]
STOP = threading.Event()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args):
        return None


def command(args, timeout=30):
    return subprocess.run(args, check=True, capture_output=True, timeout=timeout).stdout


def fetch_json(url, headers, body=None, *, timeout=HTTP_TIMEOUT):
    encoded = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=encoded, headers={"User-Agent": "tsmanager-runner/1.0", **headers})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout) as response:
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise RuntimeError("response_too_large")
    return json.loads(data)


def identity_token(*, timeout=HTTP_TIMEOUT):
    query = urllib.parse.urlencode({"audience": os.environ["TSM_AUDIENCE"]})
    result = fetch_json(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&" + query, {
        "Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
    }, timeout=timeout)
    return result["value"]


def report(action, body, *, timeout=HTTP_TIMEOUT):
    return fetch_json(f"{CONTROL}/api/proxy-runs/{ATTEMPT}/{action}", {
        "Authorization": "Bearer " + identity_token(timeout=timeout), "Content-Type": "application/json",
    }, body, timeout=timeout)


def progress(message):
    line = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " tsmanager: " + message
    print(line, flush=True)
    LOG_LINES.append(line)
    # shortcut: 仅保留最近 24 行，需要完整运行历史时改为分页存储。
    del LOG_LINES[:-LOG_LIMIT]
    try:
        report("logs", {"output": "\n".join(LOG_LINES)}, timeout=LOG_TIMEOUT)
    except (OSError, ValueError, KeyError, TypeError):
        pass  # 日志上报失败不能中断准备或关闭代理。


def bootstrap():
    for attempt in range(BOOTSTRAP_RETRIES):
        try:
            return report("bootstrap", {})
        except urllib.error.HTTPError as error:
            if error.code < 500:
                raise
        except OSError:
            pass
        if STOP.wait(2 ** (attempt + 1)):
            raise RuntimeError("runner_stopped")
    raise RuntimeError("bootstrap_failed")


def verify(path, expected):
    with open(path, "rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected:
        raise RuntimeError("binary_checksum_mismatch")


def extract(archive, names):
    with tarfile.open(archive, "r:gz") as source:
        for name in names:
            member = next(item for item in source.getmembers()
                          if pathlib.PurePosixPath(item.name).name == name)
            if not member.isfile() or member.size > MAX_DOWNLOAD:
                raise RuntimeError("binary_archive_invalid")
            with source.extractfile(member) as entry:
                target = pathlib.Path("/usr/local/bin") / name
                target.write_bytes(entry.read())
                target.chmod(0o755)


def install(directory):
    progress("Installing GOST " + GOST_VERSION)
    gost = pathlib.Path(directory) / f"gost_{GOST_VERSION}_linux_amd64.tar.gz"
    command(["gh", "release", "download", "v" + GOST_VERSION, "--repo", "go-gost/gost",
             "--pattern", gost.name, "--dir", directory], timeout=45)
    verify(gost, GOST_SHA)
    extract(gost, ["gost"])
    progress("Installing Tailscale " + TAILSCALE_VERSION)
    archive = pathlib.Path(directory) / "tailscale.tgz"
    url = f"https://pkgs.tailscale.com/stable/tailscale_{TAILSCALE_VERSION}_amd64.tgz"
    with urllib.request.urlopen(url, timeout=30) as source, archive.open("wb") as target:
        count = 0
        while chunk := source.read(1024 * 1024):
            count += len(chunk)
            if count > MAX_DOWNLOAD:
                raise RuntimeError("binary_too_large")
            target.write(chunk)
    verify(archive, TAILSCALE_SHA)
    extract(archive, ["tailscale", "tailscaled"])
    progress("Binary checksums verified")


def wait_daemon(process):
    for _ in range(50):
        if process.poll() is not None:
            raise RuntimeError("tailscale_daemon_failed")
        if pathlib.Path("/var/run/tailscale/tailscaled.sock").exists():
            return
        time.sleep(0.1)
    raise RuntimeError("tailscale_daemon_timeout")


def join(config, directory):
    command(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1",
             "net.ipv6.conf.default.disable_ipv6=1"])
    keyfile = pathlib.Path(directory) / "authkey"
    keyfile.write_text(config["authKey"])
    keyfile.chmod(0o600)
    try:
        command(["tailscale", "up", "--auth-key=file:" + str(keyfile),
                 "--hostname=" + config["hostname"], "--accept-dns=false",
                 "--accept-routes=false", "--timeout=30s"], timeout=35)
    finally:
        keyfile.unlink(missing_ok=True)
    info = json.loads(command(["tailscale", "status", "--json"]))["Self"]
    address = next(ip for ip in info["TailscaleIPs"] if ":" not in ip)
    return address, info["ID"]


def start_proxy(address, directory):
    outbound = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        outbound.connect(("1.1.1.1", 53))
        interface = outbound.getsockname()[0]
    finally:
        outbound.close()
    config = {
        "log": {"level": "fatal"},
        "services": [{"name": "test-proxy", "addr": f"{address}:1080",
                      "handler": {"type": "socks5", "metadata": {
                          "udp": True, "udpBufferSize": 65535, "notls": True}},
                      "listener": {"type": "tcp"}, "resolver": "ipv4",
                      "metadata": {"interface": interface}}],
        "resolvers": [{"name": "ipv4", "nameservers": [{"addr": "1.1.1.1", "only": "ipv4"}]}],
    }
    path = pathlib.Path(directory) / "gost.json"
    path.write_text(json.dumps(config))
    process = subprocess.Popen(["gost", "-C", str(path)], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    for _ in range(50):
        if process.poll() is not None:
            raise RuntimeError("proxy_start_failed")
        try:
            with socket.create_connection((address, 1080), timeout=0.2):
                return process
        except OSError:
            time.sleep(0.1)
    process.terminate()
    raise RuntimeError("proxy_start_timeout")


def watchdog(process, lease):
    while not STOP.wait(0.2):
        if time.time() * 1000 >= lease[0] or process.poll() is not None:
            STOP.set()
            process.terminate()
            return


def serve(config, directory):
    progress("Joining Tailnet")
    address, node_id = join(config, directory)
    progress("Starting SOCKS5 listener")
    process = start_proxy(address, directory)
    lease = [min(config["deadline"], config["jobDeadline"])]
    thread = threading.Thread(target=watchdog, args=(process, lease), daemon=True)
    thread.start()
    try:
        health_loop(process, lease, address=address, node_id=node_id)
    finally:
        STOP.set()
        process.terminate()
        process.wait(timeout=5)
        thread.join(timeout=1)


def health_loop(process, lease, *, address, node_id):
    ready = False
    progress("Checking TCP / UDP connectivity")
    while not STOP.is_set():
        try:
            public_ip = check(address)
            result = report("heartbeat", {"tailIp": address, "nodeId": node_id,
                                         "publicIp": public_ip, "tcp": True, "udp": True})
            if STOP.is_set() or process.poll() is not None:
                return
            lease[0] = result["leaseUntil"]
            if not ready:
                progress("TCP / UDP checks passed; runner ready")
                ready = True
        except urllib.error.HTTPError as error:
            if error.code in (400, 401, 403, 404, 409, 410):
                progress(f"Heartbeat rejected (HTTP {error.code})")
                return
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            pass
        STOP.wait(30)


def main():
    progress("Runner started")
    daemon = None
    with tempfile.TemporaryDirectory(prefix="tsmanager-") as directory:
        try:
            install(directory)
            progress("Requesting Tailscale enrollment")
            config = bootstrap()
            if time.time() * 1000 >= config["deadline"]:
                raise RuntimeError("prepare_timeout")
            progress("Starting tailscaled")
            daemon = subprocess.Popen(["tailscaled", "--state=mem:"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_daemon(daemon)
            serve(config, directory)
        finally:
            STOP.set()
            stop_daemon(daemon)


def stop_daemon(daemon):
    if not daemon:
        return
    try:
        command(["tailscale", "logout"], timeout=5)
    except subprocess.SubprocessError:
        pass
    daemon.terminate()
    daemon.wait(timeout=5)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    try:
        main()
    except Exception as error:
        reason = f"HTTP {error.code}" if isinstance(error, urllib.error.HTTPError) else type(error).__name__
        progress(f"runner_failed ({reason})")
        raise SystemExit(1)
