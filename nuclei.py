import os
import tempfile

from core import (
    BASE_DIR,
    base_url_for,
    ensure_results_dirs,
    load_probe_urls,
    normalize_domain,
    quote,
    read_lines,
    reset_dir,
    stream_command,
    target_dir,
    tool_exists,
)


def _default_templates():
    local = os.path.join(BASE_DIR, 'nuclei-templates')
    return local if os.path.isdir(local) else None  # None => nuclei's own managed templates


def run_nuclei_scan(domain, log, stop_event=None, template=None):
    domain = normalize_domain(domain)
    ensure_results_dirs(domain)
    out_dir = target_dir(domain, 'nuclei')
    reset_dir(out_dir)
    out_file = os.path.join(out_dir, 'nuclei.txt')

    if not tool_exists('nuclei'):
        log('[-] nuclei is not installed (run install.sh).', 'red')
        return

    subdomains = read_lines(target_dir(domain, 'subdomains.txt'))
    if not subdomains:
        log(f'[-] No live subdomains for {domain}. Run the subdomain scan first.', 'red')
        return

    templates = template or _default_templates()
    if templates and not os.path.exists(templates):
        log(f'[-] Nuclei templates not found: {templates}', 'red')
        return

    probe = load_probe_urls(domain)
    targets = [base_url_for(domain, host, probe) for host in subdomains]

    url_list = os.path.join(tempfile.gettempdir(), f'bughunter_nuclei_{os.getpid()}.txt')
    try:
        with open(url_list, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(targets) + '\n')

        cmd = f'nuclei -l {quote(url_list)} '
        if templates:
            cmd += f'-t {quote(templates)} '
        cmd += '-severity low,medium,high,critical -rate-limit 150 -timeout 8 -retries 1 -silent -nc'

        log(f'[*] Nuclei scan on {len(targets)} targets (this can take a while)...', 'default')
        findings = 0
        with open(out_file, 'w', encoding='utf-8') as outf:
            outf.write(f'# Nuclei scan: {domain}\n# Total targets: {len(targets)}\n\n')

            def _finding(line):
                nonlocal findings
                outf.write(line + '\n')
                log(line, 'default')
                findings += 1  # stdout only: stderr noise is not a finding

            result = stream_command(
                cmd,
                on_stdout=_finding,
                on_stderr=lambda line: log(f'[nuclei] {line}', 'default'),
                stop_event=stop_event,
            )

        if result.stopped:
            log('[-] Nuclei scan stopped.', 'red')
        elif not result.ok:
            log(f'[-] Nuclei exited with code {result.returncode}.', 'red')
        elif findings:
            log(f'[+] Nuclei complete: {findings} findings → {out_file}', 'light_green')
        else:
            log('[!] Nuclei found nothing (templates may need updating: nuclei -ut).', 'default')
    except Exception as exc:
        log(f'[-] Nuclei error: {exc}', 'red')
    finally:
        try:
            os.remove(url_list)
        except OSError:
            pass
