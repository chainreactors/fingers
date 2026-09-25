"""Capture explicit URLs as a repeatable, local judgeeval corpus (Python stdlib)."""
import argparse
import concurrent.futures
import datetime
import hashlib
import http.client
import io
import json
import pathlib
import subprocess
import urllib.parse


class ResponseSocket:
    def __init__(self, data):
        self.data = data

    def makefile(self, *_):
        return io.BytesIO(self.data)


def capture(url, destination, insecure):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username:
        return {"url": url, "error": "expected an HTTP(S) URL without credentials"}
    sample_id = hashlib.sha256(url.encode()).hexdigest()[:16]
    command = ["curl.exe" if __import__("os").name == "nt" else "curl",
               "--noproxy", "*", "--http1.1", "--raw", "--silent", "--show-error",
               "--include", "--connect-timeout", "3", "--max-time", "8",
               "--max-filesize", "524288", "--user-agent", "fingers-validation/1.0"]
    if insecure:
        command.append("--insecure")
    try:
        result = subprocess.run(command + [url], capture_output=True, timeout=10)
        if result.returncode:
            return {"url": url, "curl_exit": result.returncode,
                    "error": result.stderr.decode(errors="replace").strip()}
        response = http.client.HTTPResponse(ResponseSocket(result.stdout))
        response.begin()
        body = response.read(524289)
        if len(body) > 524288:
            raise ValueError("body exceeds capture limit")
        raw_path = destination / "samples" / (sample_id + ".http")
        raw_path.write_bytes(result.stdout)
        # Ignore volatile header values for duplicate detection; retain product evidence.
        ignored = {"date", "set-cookie", "etag", "last-modified", "connection",
                   "content-length", "transfer-encoding", "x-request-id"}
        stable_headers = sorted((k.lower(), v) for k, v in response.getheaders() if k.lower() not in ignored)
        semantic = json.dumps([response.status, stable_headers]).encode() + b"\n" + body
        return {"id": sample_id, "url": url, "group": parsed.hostname,
                "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "response": "samples/" + raw_path.name,
                "sha256": hashlib.sha256(result.stdout).hexdigest(),
                "content_sha256": hashlib.sha256(semantic).hexdigest(),
                "status": response.status, "body_bytes": len(body),
                "tls_verified": parsed.scheme == "https" and not insecure,
                "labels": []}
    except (OSError, ValueError, subprocess.TimeoutExpired, http.client.HTTPException) as error:
        return {"url": url, "error": str(error)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--urls", type=pathlib.Path, required=True, help="one explicit URL per line")
    parser.add_argument("--out", type=pathlib.Path, required=True, help="new corpus directory")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--insecure", action="store_true", help="allow certificate mismatch for IP captures")
    args = parser.parse_args()
    if not 1 <= args.workers <= 24:
        parser.error("workers must be between 1 and 24")
    if args.out.exists():
        parser.error("output already exists; use a new directory to preserve the snapshot")
    (args.out / "samples").mkdir(parents=True)
    urls = sorted(set(line.strip() for line in args.urls.read_text(encoding="utf-8-sig").splitlines()
                      if line.strip() and not line.startswith("#")))
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(lambda url: capture(url, args.out, args.insecure), urls))
    manifest = {"schema": 1, "scope": "products and versions supported by captured response evidence",
                "samples": [row for row in rows if "error" not in row], "generation": []}
    (args.out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    failures = [row for row in rows if "error" in row]
    (args.out / "fetch-errors.json").write_text(json.dumps(failures, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"requests": len(urls), "captured": len(manifest["samples"]),
                      "failed": len(failures), "manifest": str(args.out / "manifest.json")}))


if __name__ == "__main__":
    main()
