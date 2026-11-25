import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from datetime import datetime, timezone
from tkinter import filedialog, messagebox, scrolledtext
from urllib.parse import quote as url_quote

from PIL import Image, ImageTk

import xss
from core import (
    BASE_DIR,
    RESULTS_ROOT,
    HostProbeResult,
    base_url_for,
    ensure_results_dirs,
    extract_host,
    http_get,
    is_noise,
    is_subdomain,
    load_probe_urls,
    normalize_domain,
    parse_probe_line,
    quote,
    read_lines,
    reset_dir,
    stream_command,
    target_dir,
    tool_exists,
    validate_domain,
    write_lines,
)
from nuclei import run_nuclei_scan

_GOBIN = os.path.join(os.path.expanduser('~'), 'go', 'bin')
_GO_HTTPX = os.path.join(_GOBIN, 'httpx')
# ProjectDiscovery httpx lives in ~/go/bin; plain `httpx` may be the unrelated Python CLI.
_HTTPX = _GO_HTTPX if os.path.isfile(_GO_HTTPX) else 'httpx'

FFUF_THREADS = 40
FFUF_RATE = 150
FFUF_HOST_TIMEOUT = 900
PARAMSPIDER_TIMEOUT = 150
PROBE_TIMEOUT = 900
MAX_OUTPUT_LINES = 5000
DRAIN_BATCH = 200

_output_queue = queue.Queue()


# --------------------------------------------------------------------------
# GUI logging
# --------------------------------------------------------------------------
def _drain_queue(output_widget, root):
    drained = False
    try:
        for _ in range(DRAIN_BATCH):  # bounded so heavy output can't freeze Tk
            text, tag = _output_queue.get_nowait()
            output_widget.insert(tk.END, text, tag)
            drained = True
    except queue.Empty:
        pass
    if drained:
        extra = int(output_widget.index('end-1c').split('.')[0]) - MAX_OUTPUT_LINES
        if extra > 0:
            output_widget.delete('1.0', f'{extra + 1}.0')
        output_widget.yview(tk.END)
    root.after(50, _drain_queue, output_widget, root)


def _log(text, tag='default'):
    _output_queue.put((text + '\n', tag))


def open_results_folder():
    os.makedirs(RESULTS_ROOT, exist_ok=True)
    try:
        if sys.platform.startswith('win'):
            os.startfile(RESULTS_ROOT)
        elif sys.platform == 'darwin':
            subprocess.Popen(['open', RESULTS_ROOT])
        else:
            subprocess.Popen(['xdg-open', RESULTS_ROOT])
    except Exception as exc:
        messagebox.showerror('Error', f'Could not open results folder:\n{exc}')


def resolve_path(path):
    """Relative paths work from any cwd: try as given, then next to this script."""
    path = (path or '').strip()
    if not path or os.path.isabs(path) or os.path.exists(path):
        return path
    return os.path.join(BASE_DIR, path)


def _validated(domain):
    domain = normalize_domain(domain)
    if not validate_domain(domain):
        messagebox.showerror('Error', 'Enter a valid domain, e.g. example.com')
        return None
    return domain


# --------------------------------------------------------------------------
# Subdomain discovery + probing
# --------------------------------------------------------------------------
def write_runtime_metadata(domain):
    meta_path = target_dir(domain, 'meta', 'runtime.json')
    tools = ['subfinder', 'findomain', 'amass', 'ffuf', 'paramspider', 'waybackurls', 'kxss', 'nuclei']
    metadata = {
        'domain': domain,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'tools': {name: tool_exists(name) for name in tools},
        'httpx': tool_exists(_HTTPX),
    }
    with open(meta_path, 'w', encoding='utf-8') as handle:
        json.dump(metadata, handle, indent=2)
    return meta_path


def _enc(domain):
    return url_quote(domain, safe='')


def _src_crtsh(domain):
    data = json.loads(http_get(f'https://crt.sh/?q=%25.{_enc(domain)}&output=json', timeout=30))
    names = []
    for item in data:
        names.extend(str(item.get('name_value', '')).splitlines())
    return [name.replace('*.', '') for name in names]


def _src_certspotter(domain):
    url = f'https://api.certspotter.com/v1/issuances?domain={_enc(domain)}&include_subdomains=true&expand=dns_names'
    names = []
    for item in json.loads(http_get(url)):
        names.extend(item.get('dns_names', []))
    return [name.replace('*.', '') for name in names]


def _src_hackertarget(domain):
    text = http_get(f'https://api.hackertarget.com/hostsearch/?q={_enc(domain)}')
    return [line.split(',')[0] for line in text.splitlines()]  # rate-limit text is rejected later


def _src_otx(domain):
    data = json.loads(http_get(f'https://otx.alienvault.com/api/v1/indicators/domain/{_enc(domain)}/url_list?limit=500&page=1'))
    return [item.get('hostname', '') for item in data.get('url_list', [])]


def _src_subdomain_center(domain):
    return [str(item) for item in json.loads(http_get(f'https://api.subdomain.center/?domain={_enc(domain)}'))]


def _src_rapiddns(domain):
    html = http_get(f'https://rapiddns.io/subdomain/{_enc(domain)}?full=1', timeout=20)
    return re.findall(r'<td>([^<]+)</td>', html)


def fetch_subdomains(domain, stop_event=None):
    domain = normalize_domain(domain)
    ensure_results_dirs(domain)
    meta_path = write_runtime_metadata(domain)
    _log(f'[*] Fetching subdomains for {domain}...', 'stage')

    def _cli(binary, command, timeout):
        def _run():
            if not tool_exists(binary):
                _log(f'  [{binary}] not installed - skipping', 'default')
                return []
            out = []
            stream_command(command, on_stdout=out.append, stop_event=stop_event, timeout=timeout)
            return out
        return _run

    sources = [
        ('crt.sh', lambda: _src_crtsh(domain)),
        ('certspotter', lambda: _src_certspotter(domain)),
        ('hackertarget', lambda: _src_hackertarget(domain)),
        ('otx', lambda: _src_otx(domain)),
        ('subdomain.center', lambda: _src_subdomain_center(domain)),
        ('rapiddns', lambda: _src_rapiddns(domain)),
        ('subfinder', _cli('subfinder', f'subfinder -d {quote(domain)} -silent', 25)),
        ('findomain', _cli('findomain', f'findomain -t {quote(domain)} -q', 25)),
        ('amass', _cli('amass', f'amass enum -passive -d {quote(domain)}', 45)),
    ]

    found, lock = set(), threading.Lock()

    def _worker(name, fetch):
        if stop_event is not None and stop_event.is_set():
            return
        try:
            raw = fetch()
        except Exception as exc:
            _log(f'  [{name}] failed: {exc}', 'default')
            return
        count = 0
        with lock:
            for entry in raw:
                host = extract_host(str(entry))
                if host and is_subdomain(host, domain) and validate_domain(host) and not is_noise(host):
                    if host not in found:
                        found.add(host)
                        count += 1
        _log(f'  [{name}] +{count}', 'default')

    threads = [threading.Thread(target=_worker, args=src, daemon=True) for src in sources]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    if stop_event is not None and stop_event.is_set():
        _log('[-] Subdomain scan stopped.', 'red')
        return

    all_hosts = sorted(found)
    all_path = target_dir(domain, 'all_subdomains.txt')
    live_path = target_dir(domain, 'subdomains.txt')
    probe_path = target_dir(domain, 'meta', 'probe_results.json')
    write_lines(all_path, all_hosts)
    _log(f'[+] {len(all_hosts)} unique subdomains → {all_path}', 'light_green')
    if not all_hosts:
        write_lines(live_path, [])
        _log(f'[-] No subdomains found. Metadata: {meta_path}', 'red')
        return

    if not tool_exists(_HTTPX):
        _log('[!] httpx (ProjectDiscovery) not found - using unprobed hosts. Run install.sh.', 'red')
        write_lines(live_path, all_hosts)
        return

    _log('[*] Probing live hosts with httpx...', 'stage')
    hosts_file = None
    probe = {}
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as tmp:
            tmp.write('\n'.join(all_hosts) + '\n')
            hosts_file = tmp.name

        def _probe_line(line):
            parsed = parse_probe_line(line)
            if not parsed:
                return
            origin, url, codes, title = parsed
            host = extract_host(origin) or extract_host(url)
            if not host or not is_subdomain(host, domain):
                return
            probe[host] = HostProbeResult(host, url, codes, title)

        command = (f'{quote(_HTTPX)} -l {quote(hosts_file)} -json -status-code -title '
                   f'-tech-detect -follow-redirects -silent -no-color')
        result = stream_command(command, on_stdout=_probe_line, stop_event=stop_event, timeout=PROBE_TIMEOUT,
                                on_stderr=lambda line: _log(f'  [httpx] {line}', 'default'))
    finally:
        if hosts_file:
            try:
                os.remove(hosts_file)
            except OSError:
                pass

    if result.stopped:
        _log('[-] Probe stopped.', 'red')
        return
    if result.timed_out:
        _log('[!] httpx timed out; using partial results.', 'red')

    live = sorted(host for host, res in probe.items() if res.is_live)
    write_lines(live_path, live)
    with open(probe_path, 'w', encoding='utf-8') as handle:
        json.dump([{'host': r.host, 'url': r.url, 'codes': list(r.codes), 'title': r.title}
                   for r in probe.values()], handle, indent=2)
    for host in live:
        res = probe[host]
        _log(f'  {host} [{res.primary_code}] {res.title}', 'default')
    _log(f'[+] {len(live)} live subdomains → {live_path}', 'light_green')


# --------------------------------------------------------------------------
# Directory brute force (ffuf)
# --------------------------------------------------------------------------
def directory_scan_ffuf(domain, host, wordlist, stop_event=None, probe_urls=None):
    out_dir = target_dir(domain, 'directory')
    os.makedirs(out_dir, exist_ok=True)
    base = base_url_for(domain, host, probe_urls)
    tmp_file = os.path.join(out_dir, f'.{host}.tmp.json')
    final_file = os.path.join(out_dir, f'{host}.txt')
    # -ac auto-calibrates against wildcard / soft-404 / blanket-403 hosts
    command = (f'ffuf -w {quote(wordlist)} -u {quote(base + "/FUZZ")} '
               f'-mc 200,204,301,302,307,308,401,403 -ac -t {FFUF_THREADS} -rate {FFUF_RATE} '
               f'-timeout 8 -o {quote(tmp_file)} -of json -s')
    _log(f'[*] ffuf → {base}', 'stage')
    try:
        result = stream_command(command, on_stdout=lambda line: _log(line, 'default'),
                                on_stderr=lambda line: _log(f'  [ffuf] {line}', 'default'),
                                stop_event=stop_event, timeout=FFUF_HOST_TIMEOUT)
        if result.stopped:
            return
        if result.timed_out:
            _log(f'[!] ffuf timed out on {host}', 'red')
        if not os.path.exists(tmp_file):
            return
        with open(tmp_file, encoding='utf-8') as handle:
            data = json.load(handle)
        rows = data.get('results', [])
        if not rows:
            return
        with open(final_file, 'w', encoding='utf-8') as handle:
            handle.write(f'# FFUF Report: {host}\n\n')
            for item in rows:
                handle.write(f"Status: {item.get('status')}\nURL: {item.get('url')}\n\n")
        _log(f'[+] {len(rows)} hits → {final_file}', 'light_green')
    except (OSError, ValueError) as exc:
        _log(f'[-] ffuf result error for {host}: {exc}', 'red')
    finally:
        try:
            os.remove(tmp_file)
        except OSError:
            pass


def process_subdomains_for_scan(domain, wordlist='common.txt', stop_event=None):
    domain = normalize_domain(domain)
    ensure_results_dirs(domain)
    reset_dir(target_dir(domain, 'directory'))
    hosts = read_lines(target_dir(domain, 'subdomains.txt'))
    if not hosts:
        _log(f'[-] No subdomains for {domain}. Run the subdomain scan first.', 'red')
        return
    wordlist = resolve_path(wordlist)
    if not os.path.isfile(wordlist):
        _log(f'[-] Wordlist not found: {wordlist}', 'red')
        return
    if not tool_exists('ffuf'):
        _log('[-] ffuf is not installed.', 'red')
        return
    probe = load_probe_urls(domain)
    _log(f'[*] Directory scan on {len(hosts)} hosts...', 'stage')
    for host in hosts:
        if stop_event is not None and stop_event.is_set():
            _log('[-] Directory scan stopped.', 'red')
            return
        directory_scan_ffuf(domain, host, wordlist, stop_event, probe)
    _log('[+] Directory scan complete.', 'light_green')


# --------------------------------------------------------------------------
# ParamSpider
# --------------------------------------------------------------------------
def run_paramspider(domain, stop_event=None):
    domain = normalize_domain(domain)
    ensure_results_dirs(domain)
    out_dir = target_dir(domain, 'paramspider')
    reset_dir(out_dir)
    hosts = read_lines(target_dir(domain, 'subdomains.txt'))
    if not hosts:
        _log(f'[-] No subdomains for {domain}. Run the subdomain scan first.', 'red')
        return
    if not tool_exists('paramspider'):
        _log('[-] paramspider is not installed.', 'red')
        return
    _log(f'[*] ParamSpider on {len(hosts)} hosts...', 'stage')
    total = 0
    for host in hosts:
        if stop_event is not None and stop_event.is_set():
            _log('[-] ParamSpider stopped.', 'red')
            return
        urls = []
        # Run in a scratch dir: ParamSpider writes results/<host>.txt relative to cwd.
        with tempfile.TemporaryDirectory() as scratch:
            result = stream_command(f'paramspider -d {quote(host)}', on_stdout=urls.append,
                                    stop_event=stop_event, timeout=PARAMSPIDER_TIMEOUT, cwd=scratch)
            if result.stopped:
                _log('[-] ParamSpider stopped.', 'red')
                return
            if result.timed_out:
                _log(f'[!] ParamSpider timed out on {host}', 'red')
            for rel in (os.path.join('results', f'{host}.txt'), os.path.join('output', f'{host}.txt'), f'{host}.txt'):
                path = os.path.join(scratch, rel)
                if os.path.exists(path):
                    urls.extend(read_lines(path))
        urls = sorted({u for u in urls if u.startswith(('http://', 'https://')) and '=' in u})
        if urls:
            write_lines(os.path.join(out_dir, f'{host}.txt'), urls)
            total += len(urls)
            _log(f'  {host}: {len(urls)} parameterised URLs', 'default')
    _log(f'[+] ParamSpider complete: {total} URLs → {out_dir}', 'light_green')


# --------------------------------------------------------------------------
# Final report
# --------------------------------------------------------------------------
def generate_final_report(domain):
    domain = normalize_domain(domain)
    report = target_dir(domain, 'FINAL_REPORT.txt')
    sections = [
        ('SUBDOMAINS (live)', [target_dir(domain, 'subdomains.txt')]),
        ('DIRECTORY SCAN', [os.path.join(target_dir(domain, 'directory'), f)
                            for f in sorted(os.listdir(target_dir(domain, 'directory')))
                            if f.endswith('.txt')] if os.path.isdir(target_dir(domain, 'directory')) else []),
        ('PARAMSPIDER', [os.path.join(target_dir(domain, 'paramspider'), f)
                         for f in sorted(os.listdir(target_dir(domain, 'paramspider')))
                         if f.endswith('.txt')] if os.path.isdir(target_dir(domain, 'paramspider')) else []),
        ('XSS - KXSS', [target_dir(domain, 'xss', 'kxss.txt')]),
        ('XSS - REFLECTED PARAMETERS (candidates, not confirmed)', [target_dir(domain, 'xss', 'reflection.txt')]),
        ('NUCLEI', [target_dir(domain, 'nuclei', 'nuclei.txt')]),
    ]
    with open(report, 'w', encoding='utf-8') as handle:
        handle.write(f'FINAL REPORT: {domain}\nGenerated: {datetime.now(timezone.utc).isoformat()}\n\n')
        for title, paths in sections:
            handle.write(f'===== {title} =====\n')
            wrote = False
            for path in paths:
                lines = read_lines(path, keep_blank=True)
                if any(line.strip() for line in lines):
                    handle.write('\n'.join(lines).rstrip() + '\n')
                    wrote = True
            if not wrote:
                handle.write('(no results)\n')
            handle.write('\n')
    _log(f'[+] Final report → {report}', 'light_green')


# --------------------------------------------------------------------------
# Threading wrappers
# --------------------------------------------------------------------------
def _run_threaded(fn, stop_event, status_var, all_btns, stop_btn, label, root, *args):
    stop_event.clear()
    status_var.set(f'Running: {label}...')
    for button in all_btns:
        button.config(state='disabled')
    stop_btn.config(state='normal')

    def _restore(final):
        for button in all_btns:
            button.config(state='normal')
        stop_btn.config(state='disabled')
        status_var.set(final)

    def _run():
        final = 'Ready'
        try:
            fn(*args, stop_event=stop_event)
            if stop_event.is_set():
                final = 'Stopped'
        except Exception as exc:
            final = f'Error: {exc}'
            _log(f'[-] {exc}', 'red')
        finally:
            root.after(0, _restore, final)

    threading.Thread(target=_run, daemon=True).start()


def start_full_scan(domain, wordlist, stop_event, status_var, all_btns, stop_btn, root):
    domain = _validated(domain)
    if not domain:
        return

    def _full(stop_event=None):
        def stopped():
            return stop_event.is_set()
        _log(f'=== Full scan: {domain} ===', 'stage')
        fetch_subdomains(domain, stop_event=stop_event)
        if stopped():
            return
        process_subdomains_for_scan(domain, wordlist, stop_event=stop_event)
        if stopped():
            return
        run_paramspider(domain, stop_event=stop_event)
        if stopped():
            return
        xss.run_xss_scan(domain, _log, stop_event)
        if stopped():
            return
        run_nuclei_scan(domain, _log, stop_event)
        if stopped():
            return
        generate_final_report(domain)
        _log('=== Full scan complete ===', 'light_green')

    _run_threaded(_full, stop_event, status_var, all_btns, stop_btn, 'Full Scan', root)


def start_subdomain_scan(domain, stop_event, status_var, all_btns, stop_btn, root):
    domain = _validated(domain)
    if domain:
        _run_threaded(fetch_subdomains, stop_event, status_var, all_btns, stop_btn, 'Subdomains', root, domain)


def start_directory_scan(domain, wordlist, stop_event, status_var, all_btns, stop_btn, root):
    domain = _validated(domain)
    if domain:
        _run_threaded(process_subdomains_for_scan, stop_event, status_var, all_btns, stop_btn, 'Directory', root, domain, wordlist)


def start_paramspider(domain, stop_event, status_var, all_btns, stop_btn, root):
    domain = _validated(domain)
    if domain:
        _run_threaded(run_paramspider, stop_event, status_var, all_btns, stop_btn, 'ParamSpider', root, domain)


def start_xss_scan(domain, stop_event, status_var, all_btns, stop_btn, root):
    domain = _validated(domain)
    if not domain:
        return

    def _xss(stop_event=None):
        xss.run_xss_scan(domain, _log, stop_event)

    _run_threaded(_xss, stop_event, status_var, all_btns, stop_btn, 'XSS', root)


def start_nuclei_scan(domain, stop_event, status_var, all_btns, stop_btn, root):
    domain = _validated(domain)
    if not domain:
        return

    def _nuclei(stop_event=None):
        run_nuclei_scan(domain, _log, stop_event)

    _run_threaded(_nuclei, stop_event, status_var, all_btns, stop_btn, 'Nuclei', root)


def main():
    root = tk.Tk()
    root.title('Bug Hunter GUI')
    root.geometry('1000x1000')
    root.configure(bg='#1E1E2E')
    root.minsize(800, 700)

    stop_event = threading.Event()
    wordlist_var = tk.StringVar(value='common.txt')
    status_var = tk.StringVar(value='Ready')

    header_frame = tk.Frame(root, bg='#1E1E2E')
    header_frame.pack(pady=(20, 10))

    try:
        logo_image = Image.open(os.path.join(BASE_DIR, '13.png'))
        logo_image = logo_image.resize((80, 80), Image.LANCZOS)
        logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(header_frame, image=logo_photo, bg='#1E1E2E')
        logo_label.image = logo_photo
        logo_label.pack(side=tk.LEFT, padx=(0, 20))
    except Exception:
        pass

    tk.Label(
        header_frame,
        text='Bug Hunter - Full Scanner',
        font=('Helvetica', 26, 'bold'),
        bg='#1E1E2E',
        fg='#A6E3A1',
    ).pack(side=tk.LEFT)

    domain_frame = tk.Frame(root, bg='#1E1E2E')
    domain_frame.pack(pady=(20, 5))

    tk.Label(
        domain_frame,
        text='Enter Domain:',
        font=('Helvetica', 16, 'bold'),
        bg='#1E1E2E',
        fg='#C9CBFF',
    ).grid(row=0, column=0, padx=5)

    domain_entry = tk.Entry(
        domain_frame,
        width=40,
        bg='#2B2B35',
        fg='#FFFFFF',
        font=('Helvetica', 14),
        insertbackground='white',
        relief='flat',
        bd=5,
    )
    domain_entry.grid(row=0, column=1, padx=10, pady=5)
    domain_entry.config(highlightbackground='#1E1E2E', highlightthickness=1)

    wl_frame = tk.Frame(root, bg='#1E1E2E')
    wl_frame.pack(pady=(0, 5))

    tk.Label(
        wl_frame,
        text='Wordlist:',
        font=('Helvetica', 12),
        bg='#1E1E2E',
        fg='#C9CBFF',
    ).grid(row=0, column=0, padx=5)

    tk.Entry(
        wl_frame,
        textvariable=wordlist_var,
        width=36,
        bg='#2B2B35',
        fg='#FFFFFF',
        font=('Helvetica', 12),
        insertbackground='white',
        relief='flat',
        bd=4,
    ).grid(row=0, column=1, padx=5)

    tk.Button(
        wl_frame,
        text='Browse',
        command=lambda: wordlist_var.set(
            filedialog.askopenfilename(
                title='Select Wordlist',
                filetypes=[('Text files', '*.txt'), ('All files', '*.*')],
            ) or wordlist_var.get()
        ),
        font=('Helvetica', 11),
        bg='#2B2B35',
        fg='#C9CBFF',
        relief='flat',
        cursor='hand2',
        padx=8,
    ).grid(row=0, column=2, padx=5)

    output_text = scrolledtext.ScrolledText(
        root,
        wrap=tk.WORD,
        width=90,
        height=20,
        bg='#2B2B35',
        fg='#00FF00',
        insertbackground='white',
        font=('Courier', 14),
        relief='flat',
        bd=5,
    )
    output_text.pack(pady=15, padx=20)
    output_text.tag_configure('stage', foreground='#00FF00')
    output_text.tag_configure('default', foreground='#FFFFFF')
    output_text.tag_configure('light_green', foreground='#00FF00')
    output_text.tag_configure('red', foreground='#FF0000')

    root.after(100, _drain_queue, output_text, root)

    main_btn_frame = tk.Frame(root, bg='#1E1E2E')
    main_btn_frame.pack(pady=(0, 8))

    start_btn = tk.Button(
        main_btn_frame,
        text='Start Full Scan',
        font=('Helvetica', 14, 'bold'),
        bg='#FFA500',
        fg='#FFFFFF',
        relief='flat',
        width=20,
        height=2,
        cursor='hand2',
    )
    start_btn.grid(row=0, column=0, padx=8)

    stop_btn = tk.Button(
        main_btn_frame,
        text='Stop Scan',
        command=lambda: stop_event.set(),
        font=('Helvetica', 14, 'bold'),
        bg='#FF4444',
        fg='#FFFFFF',
        relief='flat',
        width=14,
        height=2,
        state='disabled',
        cursor='hand2',
    )
    stop_btn.grid(row=0, column=1, padx=8)

    scan_btn_frame = tk.Frame(root, bg='#1E1E2E')
    scan_btn_frame.pack(pady=(0, 8))

    small = dict(font=('Helvetica', 11, 'bold'), fg='#FFFFFF', relief='flat', width=13, height=1, cursor='hand2')
    btn_sub = tk.Button(scan_btn_frame, text='Subdomains', bg='#4A90D9', **small)
    btn_dir = tk.Button(scan_btn_frame, text='Directory', bg='#7E57C2', **small)
    btn_para = tk.Button(scan_btn_frame, text='ParamSpider', bg='#26A69A', **small)
    btn_xss = tk.Button(scan_btn_frame, text='XSS', bg='#EF5350', **small)
    btn_nuc = tk.Button(scan_btn_frame, text='Nuclei', bg='#8D6E63', **small)

    for col, button in enumerate([btn_sub, btn_dir, btn_para, btn_xss, btn_nuc]):
        button.grid(row=0, column=col, padx=5)

    all_btns = [start_btn, btn_sub, btn_dir, btn_para, btn_xss, btn_nuc]

    def _d():
        return domain_entry.get().strip()

    def _wl():
        return wordlist_var.get()

    def _args(**kw):
        return dict(stop_event=stop_event, status_var=status_var, all_btns=all_btns, stop_btn=stop_btn, root=root, **kw)

    start_btn.config(command=lambda: start_full_scan(_d(), _wl(), **_args()))
    btn_sub.config(command=lambda: start_subdomain_scan(_d(), **_args()))
    btn_dir.config(command=lambda: start_directory_scan(_d(), _wl(), **_args()))
    btn_para.config(command=lambda: start_paramspider(_d(), **_args()))
    btn_xss.config(command=lambda: start_xss_scan(_d(), **_args()))
    btn_nuc.config(command=lambda: start_nuclei_scan(_d(), **_args()))

    util_frame = tk.Frame(root, bg='#1E1E2E')
    util_frame.pack(pady=(0, 8))

    tk.Button(
        util_frame,
        text='Clear Output',
        command=lambda: output_text.delete('1.0', tk.END),
        font=('Helvetica', 11),
        bg='#2B2B35',
        fg='#C9CBFF',
        relief='flat',
        width=14,
        cursor='hand2',
    ).grid(row=0, column=0, padx=8)

    tk.Button(
        util_frame,
        text='Open Results',
        command=open_results_folder,
        font=('Helvetica', 11),
        bg='#2B2B35',
        fg='#C9CBFF',
        relief='flat',
        width=14,
        cursor='hand2',
    ).grid(row=0, column=1, padx=8)

    tk.Label(
        root,
        textvariable=status_var,
        font=('Helvetica', 11),
        bg='#2B2B35',
        fg='#A6E3A1',
        anchor='w',
        padx=10,
        pady=4,
    ).pack(fill=tk.X, padx=20, pady=(0, 5))

    tk.Label(
        root,
        text='Coded By Tmrswrr',
        font=('Kristen ITC', 12, 'italic'),
        bg='#1E1E2E',
        fg='#C9CBFF',
    ).place(relx=0.85, rely=0.97, anchor='center')

    root.mainloop()


if __name__ == '__main__':
    main()
