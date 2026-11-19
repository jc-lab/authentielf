#!/usr/bin/env python3
"""Minimal RFC 3161 time-stamp server over HTTP, backed by `openssl ts -reply`.

For end-to-end tests only: it checks AuthentiELF against an independent TSA
implementation. Usage: tsa.py <openssl-ts.cnf> <tsa.pem> <tsa.key> <port-file>
"""
import http.server
import os
import subprocess
import sys
import tempfile

CONFIG, CERT, KEY, PORT_FILE = sys.argv[1:5]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        query = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with tempfile.TemporaryDirectory() as d:
            qpath, rpath = os.path.join(d, "query.tsq"), os.path.join(d, "reply.tsr")
            with open(qpath, "wb") as f:
                f.write(query)
            r = subprocess.run(
                ["openssl", "ts", "-reply", "-config", CONFIG, "-queryfile", qpath,
                 "-signer", CERT, "-inkey", KEY, "-out", rpath],
                capture_output=True)
            if r.returncode != 0:
                self.send_error(500, r.stderr.decode(errors="replace")[:200])
                return
            with open(rpath, "rb") as f:
                body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(PORT_FILE + ".tmp", "w") as f:
    f.write(str(server.server_port))
os.rename(PORT_FILE + ".tmp", PORT_FILE)
server.serve_forever()
