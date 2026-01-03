#!/usr/bin/env python3
"""Simple HTTP JSON endpoint to serve current summary metrics.

Usage: python3 reports/summary_api.py
"""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from pathlib import Path
import logging

from generate_report import ReportGenerator

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('summary_api')


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != '/metrics':
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')
            return

        try:
            gen = ReportGenerator()
            # build merged logs and summary
            json_logs = gen.logger.get_recent_logs(limit=1000)
            csv_logs = gen._read_csv_logs(logs_dir=Path(__file__).parents[1] / 'logs')
            merged = gen._merge_logs(json_logs, csv_logs)
            summary = gen._build_summary_from_logs(merged)

            body = json.dumps(summary).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            log.exception('Failed to build metrics')
            self.send_response(500)
            self.end_headers()


def run(port=5000):
    server = HTTPServer(('127.0.0.1', port), Handler)
    log.info(f'Serving metrics on http://127.0.0.1:{port}/metrics')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == '__main__':
    run()
