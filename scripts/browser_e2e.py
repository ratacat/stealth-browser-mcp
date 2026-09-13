import asyncio
import json
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

async def child(url, output):
    sys.path.insert(0, str(ROOT / "src"))
    import server
    from models import BrowserOptions
    from PIL import Image

    with tempfile.TemporaryDirectory(prefix="stealth-e2e-profile-") as profile:
        instance = await server.browser_manager.spawn_browser(BrowserOptions(headless=True, viewport_width=960, viewport_height=640, user_data_dir=profile))
        print("RESULT " + json.dumps({"ready": instance.instance_id}), flush=True)
        try:
            while line := await asyncio.to_thread(sys.stdin.readline):
                request = json.loads(line)
                try:
                    started = time.monotonic()
                    if request["op"] == "navigate":
                        result = await server.navigate.fn(instance.instance_id, url + request.get("path", ""), timeout=request.get("timeout", 10000))
                        tab = await server.browser_manager.get_tab(instance.instance_id)
                        result["loaded"] = await tab.evaluate("document.readyState")
                    elif request["op"] == "shot":
                        target = Path(output) / (request["format"] + ("-full" if request["full"] else "-view") + ".image")
                        result = await server.take_screenshot.fn(instance.instance_id, full_page=request["full"], format=request["format"], file_path=str(target))
                        with Image.open(target) as image:
                            result["dimensions"] = image.size
                            result["image_format"] = image.format
                    elif request["op"] == "alive":
                        tab = await server.browser_manager.get_tab(instance.instance_id)
                        result = {"title": await tab.evaluate("document.title")}
                    elif request["op"] == "close":
                        result = {"closed": await server.close_instance.fn(instance.instance_id)}
                        print("RESULT " + json.dumps({"ok": True, "result": result}), flush=True)
                        break
                    else:
                        raise ValueError("Unknown command")
                    print("RESULT " + json.dumps({"ok": True, "elapsed": time.monotonic() - started, "result": result}), flush=True)
                except Exception as error:
                    print("RESULT " + json.dumps({"ok": False, "elapsed": time.monotonic() - started, "error": type(error).__name__ + ": " + str(error)}), flush=True)
        finally:
            await server.browser_manager.close_instance(instance.instance_id)

class Page(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/slow.svg"):
            time.sleep(2)
            body = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>'
            content_type = "image/svg+xml"
        else:
            image = '<img src="/slow.svg?fresh=' + str(time.time()) + '">' if self.path.startswith("/slow") else ""
            body = ('<!doctype html><title>SourceWalk browser check</title><body onload="this.dataset.loaded=\'yes\'" style="margin:0"><h1>Hostel page</h1>' + image + '<main style="height:2400px;background:linear-gradient(white,teal)">Dorms available</main><footer>End of page</footer></body>').encode()
            content_type = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def log_message(self, *_):
        pass

def receive(process):
    while line := process.stdout.readline():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    raise RuntimeError("Browser worker exited")

def request(process, body):
    process.stdin.write(json.dumps(body) + "\n")
    process.stdin.flush()
    result = receive(process)
    print(json.dumps({"command": body, **result}), flush=True)
    return result

def main():
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp(prefix="stealth-e2e-"))
    output.mkdir(parents=True, exist_ok=True)
    http = ThreadingHTTPServer(("127.0.0.1", 0), Page)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{http.server_port}"
    children = []
    logs = []
    try:
        for index in range(2):
            log = (output / f"browser-{index}.log").open("w")
            logs.append(log)
            process = subprocess.Popen([sys.executable, "-u", str(Path(__file__).resolve()), "--child", url, str(output)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
            children.append(process)
            ready = receive(process)
            assert ready.get("ready"), ready
            result = request(process, {"op": "navigate"})
            assert result["ok"], result
        assert request(children[0], {"op": "alive"})["ok"]
        assert request(children[1], {"op": "close"})["result"]["closed"]
        children[1].wait(timeout=15)
        assert request(children[0], {"op": "alive"})["ok"]
        view = request(children[0], {"op": "shot", "format": "png", "full": False})
        full = request(children[0], {"op": "shot", "format": "png", "full": True})
        jpeg = request(children[0], {"op": "shot", "format": "jpeg", "full": False})
        assert view["ok"] and full["ok"] and jpeg["ok"]
        assert full["result"]["dimensions"][1] > 2400
        assert full["result"]["dimensions"][1] > view["result"]["dimensions"][1]
        assert jpeg["result"]["image_format"] == "JPEG"
        slow = request(children[0], {"op": "navigate", "path": "/slow", "timeout": 10000})
        timeout = request(children[0], {"op": "navigate", "path": "/slow", "timeout": 150})
        assert slow["ok"] and slow["result"]["loaded"] == "complete" and slow["elapsed"] >= 1.8, slow
        assert not timeout["ok"] and "Timeout" in timeout["error"] and timeout["elapsed"] < 1.5, timeout
        assert request(children[0], {"op": "close"})["result"]["closed"]
        children[0].wait(timeout=15)
        print(json.dumps({"passed": True, "output": str(output)}))
    finally:
        for process in children:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for log in logs:
            log.close()
        http.shutdown()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        asyncio.run(child(sys.argv[2], sys.argv[3]))
    else:
        main()
