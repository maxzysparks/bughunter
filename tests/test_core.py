import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
import nuclei  # noqa: E402
import xss  # noqa: E402


class ParseProbe(unittest.TestCase):
    def test_json_uses_status_and_title_not_tech(self):
        line = '{"input":"a.example.com","url":"https://a.example.com","status_code":200,"title":"Welcome 404 page","tech":["Nginx","PHP"]}'
        origin, url, codes, title = core.parse_probe_line(line)
        self.assertEqual((origin, codes, title), ('a.example.com', (200,), 'Welcome 404 page'))

    def test_plain_text_fallback(self):
        line = 'https://a.example.com [200] [Welcome 404 page] [Nginx,PHP]'
        _o, _u, codes, title = core.parse_probe_line(line)
        self.assertEqual(codes, (200,))
        self.assertEqual(title, 'Welcome 404 page')

    def test_garbage(self):
        self.assertIsNone(core.parse_probe_line('not output'))
        self.assertIsNone(core.parse_probe_line('{bad json'))

    def test_is_live(self):
        self.assertTrue(core.HostProbeResult('h', 'u', (403,)).is_live)
        self.assertFalse(core.HostProbeResult('h', 'u', (404,)).is_live)


class Domains(unittest.TestCase):
    def test_validate(self):
        for good in ('example.com', 'a.b.example.co.uk', 'example.xn--p1ai'):
            self.assertTrue(core.validate_domain(good), good)
        for bad in ('localhost', 'a b.com', 'x.com; rm -rf /', 'https://x.com', ''):
            self.assertFalse(core.validate_domain(bad), bad)

    def test_normalize_and_scope(self):
        self.assertEqual(core.normalize_domain('https://Example.com:8443/x'), 'example.com')
        self.assertTrue(core.is_subdomain('a.example.com', 'example.com'))
        self.assertFalse(core.is_subdomain('evilexample.com', 'example.com'))

    def test_base_url_stays_in_scope(self):
        probe = {'a.example.com': 'https://evil.com/login'}
        self.assertEqual(core.base_url_for('example.com', 'a.example.com', probe), 'https://a.example.com')
        probe = {'a.example.com': 'http://www.example.com/x'}
        self.assertEqual(core.base_url_for('example.com', 'a.example.com', probe), 'http://www.example.com')


class Runner(unittest.TestCase):
    def test_collects_stdout_and_stderr(self):
        out, err = [], []
        res = core.stream_command('echo hi; echo oops 1>&2', on_stdout=out.append, on_stderr=err.append)
        self.assertTrue(res.ok)
        self.assertEqual((out, err), (['hi'], ['oops']))

    def test_timeout_on_silent_process(self):
        start = time.monotonic()
        res = core.stream_command('sleep 30', timeout=1)
        self.assertTrue(res.timed_out)
        self.assertLess(time.monotonic() - start, 8)

    def test_stop_on_silent_process(self):
        ev = threading.Event()
        threading.Timer(0.5, ev.set).start()
        start = time.monotonic()
        res = core.stream_command('sleep 30', stop_event=ev)
        self.assertTrue(res.stopped)
        self.assertLess(time.monotonic() - start, 8)

    def test_nonzero_exit_not_ok(self):
        self.assertFalse(core.stream_command('exit 3').ok)


class Xss(unittest.TestCase):
    def test_replace_and_dedupe(self):
        self.assertEqual(xss.replace_params('https://a.example.com/p?x=1&y=2#f'),
                         f'https://a.example.com/p?x={xss.MARKER}&y={xss.MARKER}')
        self.assertIsNone(xss.replace_params('https://a.example.com/p'))
        urls = ['https://a.example.com/p?x=1', 'https://a.example.com/p?x=2',
                'https://evil.com/p?x=1', 'ftp://a.example.com/p?x=1']
        self.assertEqual(len(xss.select_reflection_candidates(urls, 'example.com')), 1)

    def test_reflection_check(self):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                ctype = 'application/json' if self.path.startswith('/json') else 'text/html'
                self.send_response(200); self.send_header('Content-Type', ctype); self.end_headers()
                self.wfile.write(self.path.encode())
            def log_message(self, *a): pass
        srv = HTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f'http://127.0.0.1:{srv.server_port}'
        try:
            self.assertIsNotNone(xss._check_reflection(f'{base}/html?x={xss.MARKER}', None))
            self.assertIsNone(xss._check_reflection(f'{base}/json?x={xss.MARKER}', None))
        finally:
            srv.shutdown()


class NucleiFlow(unittest.TestCase):
    def test_counts_only_stdout_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_root, old_path = core.RESULTS_ROOT, os.environ['PATH']
            core.RESULTS_ROOT = os.path.join(tmp, 'results')
            fake = os.path.join(tmp, 'nuclei')
            with open(fake, 'w') as fh:
                fh.write('#!/bin/sh\necho "warn: noisy" 1>&2\necho "[tpl] [http] [high] https://a.example.com"\n')
            os.chmod(fake, 0o755)
            os.environ['PATH'] = tmp + os.pathsep + old_path
            try:
                core.write_lines(core.target_dir('example.com', 'subdomains.txt'), ['a.example.com'])
                logs = []
                nuclei.run_nuclei_scan('example.com', lambda t, tag='default': logs.append(t))
                self.assertTrue(any('1 findings' in l for l in logs), logs)
            finally:
                core.RESULTS_ROOT, os.environ['PATH'] = old_root, old_path


class TargetIsolation(unittest.TestCase):
    def test_per_target_dirs(self):
        self.assertNotEqual(core.target_dir('a.com', 'x'), core.target_dir('b.com', 'x'))


if __name__ == '__main__':
    unittest.main()
