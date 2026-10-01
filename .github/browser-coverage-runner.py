"""Run upstream browser tests and wait for its actual coverage upload before exit."""
import os
import base64
import hashlib
import json
from pathlib import Path
import socket
import ssl
import queue
import re
import subprocess
import sys
import threading
import time

from selenium import webdriver
from selenium.webdriver.chrome.service import Service


def main():
    # Cargo executes runners from the independent test workspace. All fixture
    # paths are rooted beside this script, independent of Cargo's working dir.
    os.chdir(Path(__file__).resolve().parent.parent)
    env = dict(os.environ, NO_HEADLESS="1", WASM_BINDGEN_TEST_ADDRESS="127.0.0.1:0")
    process = subprocess.Popen(
        ["wasm-bindgen-test-runner", *sys.argv[1:]], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    output = queue.Queue()

    def collect():
        for line in process.stdout:
            output.put(line)

    threading.Thread(target=collect, daemon=True).start()
    driver = None
    proxy = None
    try:
        deadline = time.monotonic() + 120
        address = None
        while time.monotonic() < deadline and address is None:
            if process.poll() is not None and output.empty():
                raise RuntimeError("upstream test server exited before browser startup")
            try:
                line = output.get(timeout=0.2)
            except queue.Empty:
                continue
            print(line, end="", flush=True)
            match = re.search(r"http://127\.0\.0\.1:\d+", line)
            if match:
                address = match.group()
        if address is None:
            raise RuntimeError("upstream test server startup timed out")
        fixture_path = Path("browser-fixture.json").resolve()
        fixture = json.loads(fixture_path.read_text())
        if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", fixture["upstream"]):
            raise RuntimeError("fixture must use an actual loopback door")
        if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", fixture["faults"]):
            raise RuntimeError("fault proxy must use loopback")
        tls = Path(".browser-tls").resolve()
        certificate, key = tls / "cert.pem", tls / "key.pem"
        config = tls / "Caddyfile"
        config.write_text("""{
    admin off
    auto_https off
}
https://wallet.example.test {
    bind 127.0.0.1
    tls CERT KEY
    handle /v1/logout {
        reverse_proxy FAULTS
    }
    handle /__faults {
        reverse_proxy FAULTS
    }
    handle /v1/* {
        reverse_proxy UPSTREAM
    }
    handle /__fixture {
        root * FIXTURE_ROOT
        rewrite * /browser-fixture.json
        file_server
    }
    handle {
        reverse_proxy TEST_RUNNER
    }
}
""".replace("CERT", str(certificate)).replace("KEY", str(key))
            .replace("UPSTREAM", fixture["upstream"])
            .replace("FAULTS", fixture["faults"])
            .replace("FIXTURE_ROOT", str(fixture_path.parent)).replace("TEST_RUNNER", address))
        proxy = subprocess.Popen(["caddy", "run", "--config", str(config)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.create_default_context(cafile=str(certificate))
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", 443), timeout=1) as sock:
                    with context.wrap_socket(sock, server_hostname="wallet.example.test"):
                        break
            except (OSError, ssl.SSLError):
                if proxy.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("ephemeral browser TLS endpoint did not start")
                time.sleep(0.1)
        public_key = subprocess.check_output(["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"])
        spki = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                              input=public_key, stdout=subprocess.PIPE, check=True).stdout
        pinned_fixture_key = base64.b64encode(hashlib.sha256(spki).digest()).decode()
        options = webdriver.ChromeOptions()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--no-proxy-server")
        options.add_argument("--host-resolver-rules=MAP wallet.example.test 127.0.0.1")
        # Only this ephemeral fixture key is accepted; no global TLS bypass.
        options.add_argument("--ignore-certificate-errors-spki-list=" + pinned_fixture_key)
        options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
        driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)
        driver.set_page_load_timeout(120)
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": """
            window.__coverageLog = [];
            for (const name of ['log', 'error']) {
                const original = console[name].bind(console);
                console[name] = (...args) => {
                    window.__coverageLog.push(args.map(String).join(' '));
                    original(...args);
                };
            }
            window.addEventListener('unhandledrejection', event => {
                window.__coverageError = String(event.reason);
            });
            const fetchOriginal = window.fetch.bind(window);
            window.fetch = async (...args) => {
                const response = await fetchOriginal(...args);
                if (String(args[0]).endsWith('/__wasm_bindgen/coverage')) {
                    if (!response.ok || !args[1]?.body?.byteLength) {
                        window.__coverageError = 'Coverage upload failed or was empty';
                    } else {
                        window.__coverageSaved = true;
                    }
                }
                return response;
            };
        """})
        driver.get("https://wallet.example.test")
        deadline = time.monotonic() + 120
        state = {}
        while time.monotonic() < deadline:
            state = driver.execute_script("""
                const text = (document.getElementById('output')?.textContent || '')
                    + '\\n' + window.__coverageLog.join('\\n');
                return {text, saved: window.__coverageSaved === true,
                        error: window.__coverageError || null};
            """)
            if state["error"] or "test result: FAILED" in state["text"]:
                raise RuntimeError(state["error"] or "upstream browser tests failed")
            if re.search(r"test result: ok\. [1-9][0-9]* passed", state["text"]):
                driver.set_script_timeout(30)
                captured = driver.execute_async_script("""
                    const done = arguments[0];
                    (async () => {
                        // Reuse the exact module URL loaded by upstream run.js; do not initialize a second instance.
                        const runtime = await import('./wasm-bindgen-test');
                        const bytes = runtime.__owned_test_cov_dump();
                        if (!bytes.byteLength) throw new Error('Empty actual profiling data');
                        const result = await fetch('/__wasm_bindgen/coverage', {
                            method: 'POST',
                            headers: {'Module-Signature': runtime.__owned_test_module_signature().toString()},
                            body: bytes
                        });
                        if (!result.ok) throw new Error('Upstream profile-file handler refused data');
                        done({bytes: bytes.byteLength});
                    })().catch(error => done({error: String(error.stack || error)}));
                """)
                if captured.get("error") or not captured.get("bytes"):
                    raise RuntimeError(captured.get("error", "profiling capture failed"))
                print(state["text"], flush=True)
                print("Saved actual profiling bytes:", captured["bytes"], flush=True)
                return
            time.sleep(0.1)
        print(state.get("text", ""), flush=True)
        raise RuntimeError("browser tests did not complete and upload coverage within 120 seconds")
    finally:
        if driver is not None:
            for entry in driver.get_log("browser"):
                if entry["level"] == "SEVERE":
                    print(entry["message"], file=sys.stderr)
            driver.quit()
        if proxy is not None:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=5)
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    main()
