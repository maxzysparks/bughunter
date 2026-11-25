"""Shared, GUI-free helpers for Bug Hunter.

Everything here is importable without tkinter/Pillow so it can be unit-tested.
"""
import json
import os
import queue
import re
import shlex
import shutil
import signal
import ssl
import subprocess
import threading
import time
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_ROOT = os.path.join(BASE_DIR, 'results')

_GOBIN = os.path.join(os.path.expanduser('~'), 'go', 'bin')
if os.path.isdir(_GOBIN) and _GOBIN not in os.environ.get('PATH', '').split(os.pathsep):
    os.environ['PATH'] = _GOBIN + os.pathsep + os.environ.get('PATH', '')

_ANSI_RE = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F][@-_])[0-?]*[ -/]*[@-~]')
_MULTI_NL = re.compile(r'\n+')
_URL_RE = re.compile(r'^https?://', re.IGNORECASE)

# Hostname with at least one dot. The TLD may be alphabetic or punycode (xn--...).
DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9\-]{1,59})$'
)
NOISE_RE = re.compile(
    r'^(?:url\d+|em\d+|e\.em\d+|click\d*|track\d*|bounce\d*|pm-bounces|mail\d+|smtp\d+|mta\d+|link\d+|img\d+|rs\d+)\.',
    re.IGNORECASE,
)
ALLOWED_HTTP_CODES = {200, 204, 301, 302, 307, 308, 401, 403}

_UA = 'Mozilla/5.0 (compatible; BugHunter/1.0)'


# --------------------------------------------------------------------------
# Text / host helpers
# --------------------------------------------------------------------------
def clean_output(text):
    return _MULTI_NL.sub('\n', _ANSI_RE.sub('', text)).strip()


def sanitize_filename(name):
    return re.sub(r'[^\w\-.]', '_', name)


def quote(value):
    """Quote one shell argument for the current platform."""
    if os.name == 'nt':
        return subprocess.list2cmdline([str(value)])
    return shlex.quote(str(value))


def extract_host(value):
    value = (value or '').strip().lower().rstrip('.')
    if not value:
        return ''
    if _URL_RE.match(value):
        try:
            return (urlsplit(value).hostname or '').lower().rstrip('.')
        except ValueError:
            value = re.sub(r'^https?://', '', value, flags=re.IGNORECASE)
    return value.split('/')[0].split(':')[0].strip().lower().rstrip('.')


def normalize_domain(value):
    return extract_host(value)


def validate_domain(domain):
    return bool(DOMAIN_RE.match((domain or '').strip()))


def is_subdomain(host, domain):
    host = (host or '').strip().lower().rstrip('.')
    domain = (domain or '').strip().lower().rstrip('.')
    return bool(host) and (host == domain or host.endswith('.' + domain))


def is_noise(host):
    return bool(NOISE_RE.match(host))


def which(binary):
    return shutil.which(binary)


def tool_exists(binary):
    if os.path.isabs(binary):
        return os.path.isfile(binary) and os.access(binary, os.X_OK)
    return which(binary) is not None


# --------------------------------------------------------------------------
# Per-target results layout:  results/<domain>/...
# --------------------------------------------------------------------------
def target_dir(domain, *parts):
    safe = sanitize_filename(normalize_domain(domain))
    return os.path.join(RESULTS_ROOT, safe, *parts)


def ensure_results_dirs(domain):
    for sub in ('directory', 'paramspider', 'xss', 'nuclei', 'meta'):
        os.makedirs(target_dir(domain, sub), exist_ok=True)


def reset_dir(path):
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path, exist_ok=True)


def read_lines(path, keep_blank=False):
    if not os.path.exists(path):
        return []
    with open(path, encoding='utf-8', errors='ignore') as handle:
        if keep_blank:
            return [line.rstrip('\n') for line in handle]
        return [line.strip() for line in handle if line.strip()]


def write_lines(path, lines):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as handle:
        for line in lines:
            handle.write(str(line).rstrip() + '\n')


def load_probe_urls(domain):
    """host -> live URL, from the last subdomain probe of this target."""
    path = target_dir(domain, 'meta', 'probe_results.json')
    try:
        with open(path, encoding='utf-8') as handle:
            return {item['host']: item['url'] for item in json.load(handle)}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def base_url_for(domain, host, probe_urls=None):
    """scheme://host to scan. Falls back to https and never leaves the target's scope."""
    url = (probe_urls or {}).get(host)
    if url:
        parts = urlsplit(url)
        if parts.scheme in ('http', 'https') and is_subdomain(parts.hostname, domain):
            return f'{parts.scheme}://{parts.netloc}'
    return f'https://{host}'


# --------------------------------------------------------------------------
# httpx output parsing
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class HostProbeResult:
    host: str
    url: str
    codes: tuple
    title: str = ''

    @property
    def primary_code(self):
        return self.codes[0] if self.codes else None

    @property
    def is_live(self):
        return any(code in ALLOWED_HTTP_CODES for code in self.codes)


_PLAIN_PROBE_RE = re.compile(
    r'^(?P<url>https?://\S+)\s+\[(?P<codes>\d{3}(?:\s*,\s*\d{3})*)\]'
    r'(?:\s+\[(?P<title>[^\]]*)\])?',
    re.IGNORECASE,
)


def parse_probe_line(line):
    """Parse one httpx output line (JSON preferred, plain text as fallback).

    Returns (input_host_or_url, final_url, codes_tuple, title) or None.
    """
    line = (line or '').strip()
    if not line:
        return None
    if line.startswith('{'):
        try:
            data = json.loads(line)
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        url = str(data.get('url') or '')
        origin = str(data.get('input') or url)
        status = data.get('status_code')
        codes = (int(status),) if isinstance(status, int) else ()
        title = str(data.get('title') or '').strip()
    else:
        match = _PLAIN_PROBE_RE.match(line)
        if not match:
            return None
        url = match.group('url')
        origin = url
        codes = tuple(sorted({int(c) for c in re.findall(r'\d{3}', match.group('codes'))}))
        title = (match.group('title') or '').strip()
    if not url:
        return None
    return origin, url, codes, title


# --------------------------------------------------------------------------
# HTTP helper (replaces curl | jq | grep -P pipelines; works on every OS)
# --------------------------------------------------------------------------
def fetch_url(url, timeout=15, verify=True, max_bytes=2 * 1024 * 1024):
    request = urllib.request.Request(url, headers={'User-Agent': _UA})
    context = None if verify else ssl._create_unverified_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
        ctype = resp.headers.get('Content-Type', '')
        charset = resp.headers.get_content_charset() or 'utf-8'
        raw = resp.read(max_bytes)
    try:
        body = raw.decode(charset, errors='replace')
    except LookupError:
        body = raw.decode('utf-8', errors='replace')
    return resp.status, ctype, body


def http_get(url, timeout=15):
    return fetch_url(url, timeout=timeout)[2]


# --------------------------------------------------------------------------
# Process runner: stop-aware, timeout-aware, cross-platform
# --------------------------------------------------------------------------
@dataclass
class CommandResult:
    returncode: int = None
    stopped: bool = False
    timed_out: bool = False

    @property
    def ok(self):
        return self.returncode == 0 and not self.stopped and not self.timed_out


def kill_process(proc, force=False):
    if proc.poll() is not None:
        return
    try:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(proc.pid)], capture_output=True)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL if force else signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill() if force else proc.terminate()
        except Exception:
            pass


def stream_command(command, on_stdout=None, on_stderr=None, stop_event=None,
                   timeout=None, cwd=None):
    """Run a shell command, streaming lines to callbacks.

    Unlike a bare ``readline`` loop, the stop flag and the timeout are polled
    every 0.2s, so a silent or hung tool is still stopped/timed out.
    """
    kwargs = dict(shell=True, text=True, cwd=cwd, encoding='utf-8', errors='replace',
                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if os.name == 'nt':
        kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs['start_new_session'] = True

    result = CommandResult()
    try:
        proc = subprocess.Popen(command, **kwargs)
    except OSError as exc:
        if on_stderr:
            on_stderr(f'failed to start: {exc}')
        result.returncode = -1
        return result

    lines = queue.Queue()

    def _pump(stream, tag):
        try:
            for raw in iter(stream.readline, ''):
                lines.put((tag, raw))
        except (ValueError, OSError):
            pass
        finally:
            lines.put((tag, None))

    for stream, tag in ((proc.stdout, 'out'), (proc.stderr, 'err')):
        threading.Thread(target=_pump, args=(stream, tag), daemon=True).start()

    open_streams = 2
    started = time.monotonic()
    exited_at = None
    while open_streams:
        if stop_event is not None and stop_event.is_set():
            result.stopped = True
            kill_process(proc)
            break
        if timeout and time.monotonic() - started > timeout:
            result.timed_out = True
            kill_process(proc)
            break
        try:
            tag, raw = lines.get(timeout=0.2)
        except queue.Empty:
            # A background grandchild can keep the pipes open after the tool exits.
            if proc.poll() is not None:
                exited_at = exited_at or time.monotonic()
                if time.monotonic() - exited_at > 2:
                    break
            continue
        if raw is None:
            open_streams -= 1
            continue
        cleaned = clean_output(raw)
        if not cleaned:
            continue
        callback = on_stdout if tag == 'out' else on_stderr
        if callback:
            callback(cleaned)

    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        kill_process(proc, force=True)
        proc.wait()
    result.returncode = proc.returncode
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()
        except (OSError, ValueError):
            pass
    return result
