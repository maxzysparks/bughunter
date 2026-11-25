import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core import (
    ensure_results_dirs,
    fetch_url,
    is_subdomain,
    normalize_domain,
    quote,
    reset_dir,
    stream_command,
    target_dir,
    tool_exists,
    write_lines,
)

MARKER = 'xsstest987654321'
MAX_REFLECTION_URLS = 500
REFLECTION_WORKERS = 10
WAYBACK_TIMEOUT = 600
KXSS_TIMEOUT = 900


def replace_params(url):
    """Replace every query value with MARKER (what qsreplace did). None if no params."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return None
    query = urlencode([(key, MARKER) for key, _ in pairs])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ''))


def url_signature(url):
    """Same host + path + parameter names => same endpoint; test it once."""
    parts = urlsplit(url)
    names = tuple(sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True)}))
    return (parts.netloc.lower(), parts.path, names)


def select_reflection_candidates(urls, domain, limit=MAX_REFLECTION_URLS):
    seen, picked = set(), []
    for url in urls:
        parts = urlsplit(url)
        if parts.scheme not in ('http', 'https') or '=' not in parts.query:
            continue
        if not is_subdomain(parts.hostname, domain):  # stay in scope
            continue
        sig = url_signature(url)
        if sig in seen:
            continue
        seen.add(sig)
        candidate = replace_params(url)
        if candidate:
            picked.append(candidate)
        if len(picked) >= limit:
            break
    return picked


def _check_reflection(url, stop_event):
    if stop_event is not None and stop_event.is_set():
        return None
    try:
        _status, ctype, body = fetch_url(url, timeout=10, verify=False, max_bytes=512 * 1024)
    except Exception:
        return None
    ctype = ctype.lower()
    if 'html' not in ctype and 'xml' not in ctype:  # JSON / text reflections aren't XSS
        return None
    return url if MARKER in body else None


def run_xss_scan(domain, log, stop_event=None):
    domain = normalize_domain(domain)
    ensure_results_dirs(domain)
    xss_dir = target_dir(domain, 'xss')
    reset_dir(xss_dir)

    def stopped():
        return stop_event is not None and stop_event.is_set()

    if not tool_exists('waybackurls'):
        log('[-] waybackurls is not installed (run install.sh).', 'red')
        return

    try:
        # 1) Collect historical URLs. waybackurls wants a bare domain, not https://domain
        log('[*] Collecting URLs with waybackurls...', 'stage')
        urls = []
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as tmp:
            tmp.write(domain + '\n')
        try:
            result = stream_command(
                f'waybackurls < {quote(tmp.name)}',
                on_stdout=urls.append,
                on_stderr=lambda line: log(f'[waybackurls] {line}', 'default'),
                stop_event=stop_event,
                timeout=WAYBACK_TIMEOUT,
            )
        finally:
            os.unlink(tmp.name)
        if stopped():
            log('[-] XSS scan stopped.', 'red')
            return
        if result.timed_out:
            log('[!] waybackurls timed out; continuing with partial results.', 'red')
        elif not result.ok:
            log(f'[-] waybackurls failed (exit {result.returncode}).', 'red')
            return
        urls = sorted(set(urls))
        urls_file = os.path.join(xss_dir, 'urls.txt')
        write_lines(urls_file, urls)
        log(f'[+] {len(urls)} unique URLs → {urls_file}', 'light_green')
        if not urls:
            return

        # 2) kxss
        kxss_out = os.path.join(xss_dir, 'kxss.txt')
        if tool_exists('kxss'):
            log('[*] Running KXSS scan...', 'stage')
            with open(kxss_out, 'w', encoding='utf-8') as handle:
                def _kxss_line(line):
                    handle.write(line + '\n')
                    log(line, 'default')
                result = stream_command(
                    f'kxss < {quote(urls_file)}',
                    on_stdout=_kxss_line,
                    on_stderr=lambda line: log(f'[kxss] {line}', 'default'),
                    stop_event=stop_event,
                    timeout=KXSS_TIMEOUT,
                )
            if stopped():
                log('[-] XSS scan stopped.', 'red')
                return
            if result.ok:
                log(f'[+] KXSS done → {kxss_out}', 'light_green')
            else:
                log(f'[-] KXSS did not finish cleanly (exit {result.returncode}, '
                    f'timeout={result.timed_out}); results may be partial.', 'red')
        else:
            log('[!] kxss not installed - skipping (run install.sh).', 'red')

        # 3) Reflection check: concurrent, scoped, HTML/XML responses only
        candidates = select_reflection_candidates(urls, domain)
        log(f'[*] Reflection check on {len(candidates)} unique endpoints...', 'stage')
        refl_out = os.path.join(xss_dir, 'reflection.txt')
        hits = []
        executor = ThreadPoolExecutor(max_workers=REFLECTION_WORKERS)
        try:
            futures = [executor.submit(_check_reflection, url, stop_event) for url in candidates]
            for future in as_completed(futures):
                if stopped():
                    break
                hit = future.result()
                if hit:
                    hits.append(hit)
                    log(f'[reflected] {hit}', 'default')
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        write_lines(refl_out, hits)
        if stopped():
            log('[-] XSS scan stopped.', 'red')
            return
        log(f'[+] Reflection check done: {len(hits)} reflected (candidates for manual XSS '
            f'testing, not confirmed XSS) → {refl_out}', 'light_green')
    except Exception as exc:
        log(f'[-] XSS error: {exc}', 'red')
