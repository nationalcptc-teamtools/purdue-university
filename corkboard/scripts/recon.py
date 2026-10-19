#!/usr/bin/env python3
import argparse
import concurrent.futures
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
PHASES = ('prepare', 'discovery', 'scan', 'udp', 'verify', 'web', 'review', 'push', 'all')
DISCOVERY_TCP = '21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,6379,8000,8080,8443,9200'
WEB_NAMES = {'http', 'https', 'http-proxy', 'http-alt', 'https-alt', 'ssl/http'}
WINRM_PORTS = {5985, 5986, 47001}

def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    os.chmod(temporary, 384)
    temporary.replace(path)

def networks(path):
    result = []
    if path is None:
        return result
    for number, raw in enumerate(Path(path).read_text().splitlines(), 1):
        value = raw.split('#', 1)[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4:
                raise ValueError('IPv6 needs a separate scanning profile')
            result.append(network)
        except ValueError as error:
            raise ValueError(f'{path}:{number}: {error}') from error
    return result

def targets(path, exclude=None):
    excluded = networks(exclude)
    addresses = set()
    for network in networks(path):
        if network.num_addresses > 65536:
            raise ValueError('target expansion exceeds 65,536 addresses')
        for address in network.hosts():
            if not any((address in item for item in excluded)):
                addresses.add(address)
        if len(addresses) > 65536:
            raise ValueError('target expansion exceeds 65,536 addresses')
    if not addresses:
        raise ValueError('no targets remain')
    return [str(address) for address in sorted(addresses)]

def nmap_result(path, address):
    root = ET.parse(path).getroot()
    finish = root.find('runstats/finished')
    if root.tag != 'nmaprun' or finish is None or finish.get('exit') != 'success':
        raise ValueError('Nmap XML does not establish successful completion')
    hosts = root.findall('host')
    ports, unknown, uncertain_udp, errors = (set(), set(), set(), [])
    uncertain_udp_aggregates = 0
    for host in hosts:
        addresses = [item.get('addr') for item in host.findall('address') if item.get('addrtype') in ('ipv4', 'ipv6')]
        if addresses != [address]:
            raise ValueError('Nmap output does not match the requested host')
        if host.get('timedout') == 'true':
            raise ValueError('Nmap host timed out')
        for item in host.findall('ports/port'):
            state = item.find('state')
            if state is None:
                raise ValueError('Nmap port has no state')
            port = int(item.get('portid'))
            if not 1 <= port <= 65535:
                raise ValueError('Nmap port out of range')
            if item.get('protocol') == 'tcp' and state.get('state') == 'open':
                ports.add(port)
                service = item.find('service')
                if service is None or service.get('method') != 'probed' or service.get('name') in (None, '', 'unknown'):
                    unknown.add(port)
            if item.get('protocol') == 'udp' and state.get('state') == 'open|filtered':
                uncertain_udp.add(port)
        if any((scan.get('protocol') == 'udp' for scan in root.findall('scaninfo'))):
            uncertain_udp_aggregates += sum((int(item.get('count', '0')) for item in host.findall('ports/extraports') if item.get('state') == 'open|filtered'))
        for script in host.findall('.//script'):
            output = script.get('output', '').lower()
            if 'script execution failed' in output or 'timed out' in output:
                errors.append(script.get('id'))
    return {'ports': sorted(ports), 'unidentified': sorted(unknown), 'uncertain_udp': sorted(uncertain_udp), 'uncertain_udp_aggregate_count': uncertain_udp_aggregates, 'script_errors': errors}

def live_hosts(path):
    root = ET.parse(path).getroot()
    finish = root.find('runstats/finished')
    if root.tag != 'nmaprun' or finish is None or finish.get('exit') != 'success':
        raise ValueError('Nmap XML does not establish successful completion')
    live = set()
    for host in root.findall('host'):
        status = host.find('status')
        address = next((item.get('addr') for item in host.findall('address') if item.get('addrtype') == 'ipv4'), None)
        if status is not None and status.get('state') == 'up' and address:
            live.add(ipaddress.ip_address(address))
    return [str(address) for address in sorted(live)]

def web_urls(paths):
    urls = set()
    for path in paths:
        root = ET.parse(path).getroot()
        for host in root.findall('host'):
            address = next((item.get('addr') for item in host.findall('address') if item.get('addrtype') == 'ipv4'), None)
            for item in host.findall('ports/port'):
                state, service = (item.find('state'), item.find('service'))
                port = int(item.get('portid'))
                if address is None or item.get('protocol') != 'tcp' or state is None or (state.get('state') != 'open') or (service is None) or (port in WINRM_PORTS):
                    continue
                name = service.get('name', '')
                tls = service.get('tunnel') == 'ssl' or name in ('https', 'https-alt')
                if name in WEB_NAMES or (tls and name.startswith('http')):
                    urls.add(f"{('https' if tls else 'http')}://{address}:{port}/")
    return sorted(urls)

class Workflow:

    def __init__(self, args, directory, manifest):
        self.args, self.directory, self.manifest = (args, directory, manifest)
        self.processes, self.process_lock = (set(), threading.Lock())
        self.stopping = threading.Event()
        self.rotation = 0

    def save(self):
        atomic_json(self.directory / 'manifest.json', self.manifest)

    def command(self, phase, address, prefix, ports=()):
        a = self.args
        privileged = not a.connect_scan
        if phase == 'discovery':
            cmd = [a.nmap, '-sn', '-n', '-T4', '-PS' + DISCOVERY_TCP]
            if privileged:
                cmd += ['-PE', '-PP', '-PA80,443,3389', '-PU53,137,161']
            cmd += ['--reason', '-iL', str(self.directory / 'targets.txt'), '-oA', str(prefix)]
        elif phase == 'scan' and (not self.manifest['omitted'].get('rustscan')):
            nmap = ['-sS', '-O', '--osscan-limit'] if privileged else ['-sT']
            cmd = [shutil.which(a.rustscan) or a.rustscan, '--no-config', '--no-banner', '-a', address, '-r', '1-65535', '-b', str(a.rust_batch), '-t', str(a.rust_timeout_ms), '--tries', str(a.rust_tries), '--ulimit', '8192', '--', *nmap, '-Pn', '-n', '-sV', '-sC', '--reason', '-oA', str(prefix)]
        else:
            cmd = [a.nmap, '-sT' if a.connect_scan else '-sS', '-Pn', '-n', '-T3']
            if phase == 'scan':
                cmd += ['-p-', '-sV', '-sC']
            elif phase == 'verify':
                cmd += ['-p-']
                if privileged:
                    cmd += ['-O', '--osscan-limit']
            elif phase == 'udp':
                cmd[1] = '-sU'
                cmd += ['--top-ports', str(a.udp_top), '-sV']
            else:
                cmd += ['-p', ','.join(map(str, ports)), '-sV', '--version-all', '-sC']
            cmd += ['--reason', '--stats-every', '30s', address, '-oA', str(prefix)]
        if privileged and os.geteuid() != 0:
            cmd = ['sudo', '-n'] + cmd
        return cmd

    def add_job(self, phase, address, ports=()):
        key = f'{phase}:{address}'
        previous = self.manifest['jobs'].get(key)
        if previous:
            return
        attempt = 1 + max([previous.get('attempt', 0) if previous else 0] + [item['attempt'] for item in self.manifest.get('previous_attempts', []) if item['phase'] == phase and item['ip'] == address])
        prefix = self.directory / f'{address}-{phase}-{attempt}'
        self.manifest['jobs'][key] = {'phase': phase, 'ip': address, 'ports_requested': list(ports), 'attempt': attempt, 'prefix': str(prefix), 'state': 'pending', 'command': self.command(phase, address, prefix, ports), 'upload': 'pending'}

    def allowed(self, phase):
        if self.args.phase == 'all':
            return phase not in ('verify', 'verify-detail') or self.args.verify
        return phase in {'discovery': ('discovery',), 'scan': ('scan',), 'udp': ('udp',), 'verify': ('verify', 'verify-detail')}.get(self.args.phase, ())

    def host_jobs(self):
        live = self.manifest.get('live')
        if live is None:
            return
        for address in live:
            for phase in ('scan', 'udp', 'verify'):
                if not self.allowed(phase):
                    continue
                if phase == 'udp' and self.args.connect_scan:
                    self.manifest['omitted']['udp'] = 'connect-scan mode; raw-packet privilege not used'
                    continue
                self.add_job(phase, address)

    def prepare_jobs(self):
        if self.args.rescan:
            for key, job in list(self.manifest['jobs'].items()):
                if self.allowed(job['phase']):
                    self.manifest.setdefault('previous_attempts', []).append(dict(job))
                    del self.manifest['jobs'][key]
            if self.allowed('discovery') and (not self.args.assume_live):
                self.manifest.pop('live', None)
        if not shutil.which(self.args.rustscan) or self.manifest['omitted'].get('rustscan_incompatible'):
            self.manifest['omitted']['rustscan'] = 'RustScan unavailable/incompatible; Nmap scans all ports instead'
        if self.args.assume_live and self.manifest.get('live') is None:
            self.manifest['live'] = list(self.manifest['targets'])
            self.manifest['omitted']['discovery'] = '--assume-live: every target treated as up'
        if self.allowed('discovery') and self.manifest.get('live') is None:
            self.add_job('discovery', 'range')
        elif self.args.phase in ('scan', 'udp', 'verify') and self.manifest.get('live') is None:
            raise ValueError('no live-host list yet; run --phase discovery first (or use --assume-live)')
        self.host_jobs()
        for key, job in list(self.manifest['jobs'].items()):
            if job['state'] == 'completed':
                artifact = Path(job['artifact'])
                if not artifact.exists() or digest(artifact) != job['sha256']:
                    raise ValueError(f'changed/missing completed artifact: {artifact}')
            elif job['state'] != 'pending' and self.allowed(job['phase']):
                phase, address = (job['phase'], job['ip'])
                attempt = job['attempt'] + 1
                prefix = self.directory / f'{address}-{phase}-{attempt}'
                self.manifest.setdefault('previous_attempts', []).append(dict(job))
                job.update(attempt=attempt, prefix=str(prefix), state='pending', upload='pending')
                job['command'] = self.command(phase, address, prefix, job['ports_requested'])

    def execute(self, command, stdout, stderr, timeout=None):
        if self.stopping.is_set():
            raise InterruptedError('workflow interrupted')
        with open(stdout, 'wb') as out, open(stderr, 'wb') as err:
            process = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True)
            with self.process_lock:
                self.processes.add(process)
                if self.stopping.is_set():
                    os.killpg(process.pid, signal.SIGTERM)
            try:
                try:
                    return process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    return 124
            finally:
                with self.process_lock:
                    self.processes.discard(process)

    def stop(self):
        self.stopping.set()
        with self.process_lock:
            processes = list(self.processes)
            for process in processes:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
        for process in processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)

    def run_job(self, job):
        result = dict(job)
        prefix = Path(job['prefix'])
        try:
            for suffix in ('.xml', '.nmap', '.gnmap'):
                Path(str(prefix) + suffix).touch(mode=384, exist_ok=False)
            result['returncode'] = self.execute(job['command'], str(prefix) + '.stdout', str(prefix) + '.stderr')
            if result['returncode']:
                raise ValueError(f"scanner exited {result['returncode']}")
            artifact = Path(str(prefix) + '.xml')
            if job['phase'] == 'discovery':
                result['live'] = live_hosts(artifact)
            elif job['phase'] == 'scan' and artifact.stat().st_size == 0 and (not self.manifest['omitted'].get('rustscan')):
                artifact = Path(str(prefix) + '.stdout')
                result.update(ports=[], unidentified=[], no_open_ports=True)
            else:
                result.update(nmap_result(artifact, job['ip']))
            result.update(state='completed', artifact=str(artifact), sha256=digest(artifact))
        except (OSError, ValueError, ET.ParseError) as error:
            result.update(state='failed', error=str(error))
        result['finished_at'] = time.time()
        return result

    def follow_up(self, job):
        if job['state'] != 'completed':
            return
        if job['phase'] == 'discovery':
            self.manifest['live'] = job['live']
            self.host_jobs()
        if job['phase'] in ('scan', 'verify'):
            scan = self.manifest['jobs'].get('scan:' + job['ip'])
            verify = self.manifest['jobs'].get('verify:' + job['ip'])
            if scan and verify and (scan['state'] == verify['state'] == 'completed'):
                resolved = set(scan['ports']) - set(scan.get('unidentified', []))
                needed = sorted(set(verify['ports']) - resolved)
                if needed:
                    self.add_job('verify-detail', job['ip'], needed)

    def upload(self, job):
        if self.args.no_push or job.get('no_open_ports') or job['state'] != 'completed':
            return
        if job.get('upload') == 'completed':
            return
        artifact = Path(job['artifact'])
        if not artifact.exists() or digest(artifact) != job['sha256']:
            raise ValueError(f'changed/missing artifact for upload: {artifact}')
        command = [self.args.cork, 'push', job['artifact'], '--vantage', self.manifest['vantage']]
        job['upload_command'] = command
        try:
            prefix = job['prefix']
            code = self.execute(command, prefix + '.push.stdout', prefix + '.push.stderr', timeout=30)
            job['upload'] = 'completed' if code == 0 else 'pending'
            job['upload_returncode'] = code
        except OSError as error:
            job['upload_error'] = str(error)
            job['upload'] = 'pending'

    def upload_job(self, job):
        copy = dict(job)
        self.upload(copy)
        return copy

    def next_job(self):
        pending = [(key, job) for key, job in self.manifest['jobs'].items() if job['state'] == 'pending' and self.allowed(job['phase'])]
        for key, job in pending:
            if job['phase'] in ('discovery', 'verify-detail'):
                return (key, job)
        phases = ('scan', 'udp', 'verify')
        for offset in range(len(phases)):
            index = (self.rotation + offset) % len(phases)
            for key, job in pending:
                if job['phase'] == phases[index]:
                    self.rotation = (index + 1) % len(phases)
                    return (key, job)
        return None

    def run(self):
        self.prepare_jobs()
        self.save()
        for job in list(self.manifest['jobs'].values()):
            self.follow_up(job)
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.args.workers)
        running = {}
        uploader = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        uploads = {}
        try:
            for key, job in self.manifest['jobs'].items():
                if job['state'] == 'completed' and (not job.get('no_open_ports')) and (job.get('upload') != 'completed') and (not self.args.no_push):
                    uploads[uploader.submit(self.upload_job, dict(job))] = key
            while True:
                for future in list(uploads):
                    if future.done():
                        self.manifest['jobs'][uploads.pop(future)] = future.result()
                        self.save()
                while len(running) < self.args.workers:
                    next_item = self.next_job()
                    if not next_item:
                        break
                    key, job = next_item
                    job.update(state='running', started_at=time.time())
                    print('RUN', shlex.join(job['command']), flush=True)
                    self.save()
                    running[executor.submit(self.run_job, dict(job))] = key
                if not running:
                    break
                completed, _ = concurrent.futures.wait(running, timeout=1, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in completed:
                    key = running.pop(future)
                    job = future.result()
                    self.manifest['jobs'][key] = job
                    self.follow_up(job)
                    if job['state'] == 'completed' and (not job.get('no_open_ports')) and (not self.args.no_push):
                        uploads[uploader.submit(self.upload_job, dict(job))] = key
                    self.save()
                    print(job['state'].upper(), key, job.get('error', ''), flush=True)
            for future, key in uploads.items():
                self.manifest['jobs'][key] = future.result()
                self.save()
        except BaseException:
            self.stop()
            raise
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
            uploader.shutdown(wait=True, cancel_futures=True)
            self.save()

    def web(self):
        sources = [job['artifact'] for job in self.manifest['jobs'].values() if job['state'] == 'completed' and (not job.get('no_open_ports')) and (job['phase'] in ('scan', 'verify-detail'))]
        urls = web_urls(sources)
        state = self.manifest.get('web') or {}
        if state.get('urls') != urls or state.get('state') != 'completed':
            if urls and (not shutil.which(self.args.gowitness)):
                self.manifest['omitted']['web'] = 'gowitness unavailable; no screenshots taken'
                self.save()
                return
            state = {'urls': urls, 'state': 'pending', 'upload': 'pending'}
            if urls:
                listing, prefix = (self.directory / 'web-urls.txt', self.directory / 'web')
                listing.write_text('\n'.join(urls) + '\n')
                jsonl, shots = (self.directory / 'web.jsonl', self.directory / 'web-shots')
                jsonl.unlink(missing_ok=True)
                command = [self.args.gowitness, 'scan', 'file', '-f', str(listing), '--screenshot-path', str(shots), '--write-jsonl', '--write-jsonl-file', str(jsonl), '-q']
                state['command'] = command
                print('RUN', shlex.join(command), flush=True)
                code = self.execute(command, str(prefix) + '.stdout', str(prefix) + '.stderr', timeout=1800)
                if code or not jsonl.exists():
                    state.update(state='failed', error=f'gowitness exited {code}')
                else:
                    state.update(state='completed', artifact=str(jsonl), screenshots=str(shots), sha256=digest(jsonl))
            else:
                state.update(state='completed', upload='completed')
            self.manifest['web'] = state
            self.save()
        self.upload_web()

    def upload_web(self):
        state = self.manifest.get('web')
        if self.args.no_push or not state or state.get('state') != 'completed' or (state.get('upload') == 'completed'):
            return
        command = [self.args.cork, 'push', state['artifact'], '--type', 'gowitness', '--screenshots', state['screenshots']]
        try:
            code = self.execute(command, str(self.directory / 'web.push.stdout'), str(self.directory / 'web.push.stderr'), timeout=120)
            state.update(upload='completed' if code == 0 else 'pending', upload_returncode=code)
        except OSError as error:
            state.update(upload='pending', upload_error=str(error))
        self.save()

    def push_pending(self):
        if self.args.no_push:
            return
        for job in self.manifest['jobs'].values():
            self.upload(job)
            self.save()
        self.upload_web()

    def review(self):
        jobs = self.manifest['jobs']
        lines = ['Scan review', '===========', '']
        failed, pending_uploads = (0, 0)
        for key, job in jobs.items():
            lines.append(f"{key}: {job['state']}")
            if job['state'] != 'completed':
                failed += 1
                lines.append('  Recover: ' + shlex.join(job['command']))
            if job['state'] == 'completed' and (not job.get('no_open_ports')) and (job.get('upload') != 'completed'):
                pending_uploads += 1
                command = [self.args.cork, 'push', job['artifact'], '--vantage', self.manifest['vantage']]
                lines.append('  Upload: ' + shlex.join(command))
            for field in ('uncertain_udp', 'uncertain_udp_aggregate_count', 'script_errors'):
                if job.get(field):
                    lines.append(f'  {field}: {job[field]}')
        live = self.manifest.get('live')
        if live is not None:
            lines.append(f"Live hosts: {len(live)} of {len(self.manifest['targets'])} targets")
        for address in live or []:
            unresolved = set()
            for item in sorted(jobs.values(), key=lambda job: job.get('finished_at', 0)):
                if item['ip'] == address and item['state'] == 'completed' and (item['phase'] in ('scan', 'verify-detail')):
                    unresolved.difference_update(item.get('ports', []))
                    unresolved.update(item.get('unidentified', []))
            if unresolved:
                lines.append(f'{address} unidentified services: {sorted(unresolved)}')
            scan, verify = (jobs.get('scan:' + address), jobs.get('verify:' + address))
            if scan and verify and (scan.get('ports') is not None) and (verify.get('ports') is not None):
                lines.append(f"{address} scan-only: {sorted(set(scan['ports']) - set(verify['ports']))}; full-sweep-only: {sorted(set(verify['ports']) - set(scan['ports']))}")
        web = self.manifest.get('web')
        if web:
            lines.append(f"web: {web['state']}, {len(web['urls'])} URLs")
            if web['state'] != 'completed':
                failed += 1
                lines.append('  Recover: ' + shlex.join(web.get('command', [])))
            elif web.get('upload') != 'completed' and (not self.args.no_push):
                pending_uploads += 1
                lines.append('  Upload: ' + shlex.join([self.args.cork, 'push', web['artifact'], '--type', 'gowitness', '--screenshots', web['screenshots']]))
        lines.append('Omitted: ' + json.dumps(self.manifest.get('omitted', {})))
        lines.append(f'Unfinished/failed jobs: {failed}; pending uploads: {pending_uploads}')
        text = '\n'.join(lines) + '\n'
        (self.directory / 'review.txt').write_text(text)
        (self.directory / 'commands.sh').write_text('#!/usr/bin/env bash\n' + '\n'.join((shlex.join(job['command']) for job in jobs.values())) + '\n')
        print(text)
        return 1 if failed or (pending_uploads and (not self.args.no_push)) else 0

def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--targets')
    p.add_argument('--exclude')
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--vantage')
    p.add_argument('--phase', choices=PHASES, default='all')
    p.add_argument('--workers', type=int, default=2)
    p.add_argument('--rust-batch', type=int, default=4500)
    p.add_argument('--rust-timeout-ms', type=int, default=1500)
    p.add_argument('--rust-tries', type=int, default=2)
    p.add_argument('--udp-top', type=int, default=100)
    p.add_argument('--cork', default='cork')
    p.add_argument('--nmap', default='nmap')
    p.add_argument('--rustscan', default='rustscan')
    p.add_argument('--gowitness', default='gowitness')
    for name in ('no-push', 'resume', 'dry-run', 'connect-scan', 'rescan', 'verify', 'assume-live'):
        p.add_argument('--' + name, action='store_true')
    return p

def preflight(args, manifest):
    for tool in (args.nmap,):
        if not shutil.which(tool):
            raise ValueError(f'required tool missing: {tool}')
    if not args.no_push and (not shutil.which(args.cork)):
        print('Corkboard CLI unavailable; scans will retain pending uploads', file=sys.stderr)
    versions = {}
    for tool in (args.nmap, args.rustscan):
        if shutil.which(tool):
            result = subprocess.run([tool, '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode:
                if tool == args.rustscan:
                    manifest['omitted']['rustscan_incompatible'] = 'version query failed'
                    continue
                raise ValueError(f'cannot query tool version: {tool}')
            versions[tool] = result.stdout.strip()
    if args.phase in ('all', 'scan') and shutil.which(args.rustscan):
        help_text = subprocess.run([args.rustscan, '--help'], capture_output=True, text=True, timeout=10)
        for flag in ('--no-config', '--no-banner', '--batch-size', '--tries', '--ulimit'):
            if flag not in help_text.stdout:
                manifest['omitted']['rustscan_incompatible'] = 'missing ' + flag
    if not args.connect_scan and os.geteuid() != 0:
        subprocess.run(['sudo', '-v'], check=True)
    if args.resume and manifest.get('versions') and (manifest['versions'] != versions):
        raise ValueError('tool versions changed; keep original tools or start a new run')
    manifest['versions'] = versions
    manifest['descriptor_limits'] = list(resource.getrlimit(resource.RLIMIT_NOFILE))

def main(argv=None):
    raw_args = list(sys.argv[1:] if argv is None else argv)
    args = parser().parse_args(raw_args)
    provided = {value.split('=', 1)[0] for value in raw_args if value.startswith('--')}
    directory = args.out.resolve()
    settings = {name: getattr(args, name) for name in ('workers', 'rust_batch', 'rust_timeout_ms', 'rust_tries', 'udp_top', 'connect_scan', 'nmap', 'rustscan', 'verify', 'assume_live')}
    if any((settings[name] < 1 for name in ('workers', 'rust_batch', 'rust_timeout_ms', 'rust_tries', 'udp_top'))):
        raise ValueError('worker counts, port counts and timing settings must be positive')
    path = directory / 'manifest.json'
    if args.resume:
        manifest = json.loads(path.read_text())
        for name, value in manifest['settings'].items():
            if '--' + name.replace('_', '-') not in provided:
                setattr(args, name, value)
                settings[name] = value
        if manifest['settings'] != settings:
            raise ValueError('resume settings differ; use original settings or a new output directory')
        if args.targets and targets(args.targets, args.exclude) != manifest['targets']:
            raise ValueError('resume target list differs')
        if args.vantage and args.vantage != manifest['vantage']:
            raise ValueError('resume vantage differs')
    else:
        if not args.targets or not args.vantage:
            raise ValueError('new runs require --targets and --vantage')
        if directory.exists():
            raise ValueError('output directory exists; use --resume or choose a new directory')
        manifest = {'format': 1, 'targets': targets(args.targets, args.exclude), 'vantage': args.vantage, 'settings': settings, 'jobs': {}, 'omitted': {}}
    if args.workers > 64 or args.udp_top > 65535 or args.rust_tries > 255:
        raise ValueError('workers <=64, UDP port count <=65535, RustScan tries <=255 required')
    if args.phase == 'udp' and args.connect_scan:
        raise ValueError('UDP requires the privileged profile')
    workflow = Workflow(args, directory, manifest)
    if args.dry_run:
        if args.phase in ('prepare', 'review', 'push'):
            print(args.phase, len(manifest['targets']), 'targets; no actions executed')
            return 0
        workflow.prepare_jobs()
        for job in manifest['jobs'].values():
            print(shlex.join(job['command']))
        return 0
    directory.mkdir(mode=448, parents=True, exist_ok=True)
    with open(directory / '.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('another workflow owns this run directory') from error
        if args.resume and json.loads(path.read_text()) != manifest:
            raise ValueError('manifest changed while acquiring lock; retry resume')
        os.umask(63)
        (directory / 'targets.txt').write_text('\n'.join(manifest['targets']) + '\n')
        if args.phase not in ('prepare', 'review', 'push', 'web'):
            preflight(args, manifest)
        workflow.save()
        if args.phase == 'prepare':
            return 0
        if args.phase == 'push':
            workflow.push_pending()
        elif args.phase == 'web':
            workflow.web()
        elif args.phase != 'review':
            stop = lambda *_: (_ for _ in ()).throw(KeyboardInterrupt())
            old_handlers = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGHUP)}
            try:
                workflow.run()
                if args.phase == 'all':
                    workflow.web()
            except KeyboardInterrupt:
                print('Interrupted; artifacts retained. Resume this directory.', file=sys.stderr)
                return 130
            finally:
                for sig, handler in old_handlers.items():
                    signal.signal(sig, handler)
        return workflow.review()
if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError, ET.ParseError) as error:
        print(f'recon: {error}', file=sys.stderr)
        sys.exit(1)
