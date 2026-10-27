"""Portable, standard-library access-log analysis engine for LogScope."""
from collections import Counter, defaultdict
from datetime import datetime
import ipaddress
import re

LINE_RE = re.compile(
    r'^([0-9A-Fa-f:.]+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+'
    r'"([A-Z]+)\s+([^\s"]+)\s+HTTP/[0-9.]+"\s+(\d{3})\s+(\d+|-).*$'
)
SQL_RE = re.compile(
    r'(union(%20|\+|\s)+select)|(\bor(%20|\+|\s)*1(%20|\+|\s)*=(%20|\+|\s)*1\b)'
    r"|((%27|')[^&]*(%20|\+|\s)+(or|and)(%20|\+|\s)+[^&]*=)|(%27(%20|\+|\s)*or)", re.I
)
TRAVERSAL_RE = re.compile(r'(\.\./)|(\.\.\\)|(%2e%2e(%2f|%5c))', re.I)
AUTH_RE = re.compile(r'(/login|/signin|/auth)(/|\?|$)', re.I)


def _parse(data):
    entries, malformed = [], 0
    for line in data.splitlines():
        match = LINE_RE.match(line)
        if not match:
            malformed += 1
            continue
        ip, stamp, method, path, status, _size = match.groups()
        try:
            ipaddress.ip_address(ip)
            when = datetime.strptime(stamp[:20], '%d/%b/%Y:%H:%M:%S')
            epoch = when.timestamp()
            entries.append({'ip': ip, 'timestamp': stamp, 'method': method,
                            'path': path, 'status': int(status), 'epoch': epoch})
        except (ValueError, OverflowError, OSError):
            malformed += 1
    if not entries:
        raise ValueError('No valid access-log entries found')
    return entries, malformed


def _bounds(rows):
    return min(rows, key=lambda x: x['epoch']), max(rows, key=lambda x: x['epoch'])


def _window(rows, seconds):
    rows = sorted(rows, key=lambda x: x['epoch'])
    left = best_left = best_right = 0
    for right, row in enumerate(rows):
        while row['epoch'] - rows[left]['epoch'] > seconds:
            left += 1
        if right + 1 - left > best_right - best_left:
            best_left, best_right = left, right + 1
    return rows[best_left:best_right]


def analyze(data, fail_threshold=10, window_seconds=300, rps_threshold=5.0):
    """Analyze UTF-8 log text and return the JSON-serializable API report."""
    entries, malformed = _parse(data)
    by_ip = defaultdict(list)
    endpoint_counts = defaultdict(Counter)
    for row in entries:
        by_ip[row['ip']].append(row)
        endpoint_counts[row['path']][row['status']] += 1

    findings, ip_reports = [], []
    for ip, rows in by_ip.items():
        ordered = sorted(rows, key=lambda x: x['epoch'])
        auth = [x for x in rows if x['status'] == 401]
        burst = _window(rows, window_seconds)
        statuses = Counter(x['status'] for x in rows)
        first, last = _bounds(rows)

        if auth:
            group = _window(auth, window_seconds)
            n = len(group)
            if n >= fail_threshold:
                findings.append({'ip': ip, 'type': 'Brute Force Activity',
                    'severity': 'CRITICAL' if n >= fail_threshold * 2 else 'HIGH', 'count': n, 'rate': 0,
                    'firstSeen': group[0]['timestamp'], 'lastSeen': group[-1]['timestamp'],
                    'evidence': group[0]['path'], 'reason': f'{n} HTTP 401 authentication responses in '
                    f'{int(group[-1]["epoch"]-group[0]["epoch"])} seconds (threshold {fail_threshold} per {window_seconds} seconds).'})

        if len(rows) >= 2 and burst:
            duration = burst[-1]['epoch'] - burst[0]['epoch']
            rate = len(burst) / max(duration, 1)
            if rate >= rps_threshold:
                findings.append({'ip': ip, 'type': 'Traffic Spike',
                    'severity': 'CRITICAL' if rate >= rps_threshold * 2 else 'HIGH', 'count': len(burst), 'rate': rate,
                    'firstSeen': burst[0]['timestamp'], 'lastSeen': burst[-1]['timestamp'],
                    'evidence': f'{len(burst)} requests', 'reason': f'{len(burst)} requests; peak {rate:.1f} requests/sec '
                    f'over {int(duration)} seconds (threshold {rps_threshold:g} requests/sec).'})

        for code in (403, 404):
            n = statuses[code]
            if n >= 5:
                findings.append({'ip': ip, 'type': 'Repeated HTTP Errors', 'severity': 'HIGH' if n >= 20 else 'MEDIUM',
                    'count': n, 'rate': 0, 'firstSeen': first['timestamp'], 'lastSeen': last['timestamp'],
                    'evidence': f'HTTP {code}', 'reason': f'{n} HTTP {code} responses.'})

        for label, regex in (('SQL Injection Indicator', SQL_RE), ('Directory Traversal Indicator', TRAVERSAL_RE)):
            matched = [x for x in rows if regex.search(x['path'])]
            if matched:
                a, b = _bounds(matched)
                evidence = matched[0]['path']
                findings.append({'ip': ip, 'type': label, 'severity': 'MEDIUM', 'count': len(matched), 'rate': 0,
                    'firstSeen': a['timestamp'], 'lastSeen': b['timestamp'], 'evidence': evidence,
                    'reason': f'{len(matched)} request target(s) matched a rule-based indicator. Representative target: {evidence}'})

        peak, left = 0.0, 0
        for right, row in enumerate(ordered):
            while left < right and row['epoch'] - ordered[left]['epoch'] > window_seconds:
                left += 1
            peak = max(peak, (right + 1 - left) / max(row['epoch'] - ordered[left]['epoch'], 1))
        timeline = [{'timestamp': x['timestamp'], 'method': x['method'], 'endpoint': x['path'], 'status': x['status']} for x in rows]
        ip_reports.append({'ip': ip, 'totalRequests': len(rows), 'auth401Responses': statuses[401],
            'authEndpoint401': sum(x['status'] == 401 and AUTH_RE.search(x['path']) is not None for x in rows),
            'peakRps': peak, 'firstSeen': first['timestamp'], 'lastSeen': last['timestamp'],
            'statuses': {str(k): v for k, v in sorted(statuses.items())}, 'timeline': timeline})

    overall_first, overall_last = _bounds(entries)
    suspicious = len({x['ip'] for x in findings})
    endpoints = [{'endpoint': path, 'requests': sum(counts.values()), '401': counts[401], '403': counts[403], '404': counts[404]}
                 for path, counts in sorted(endpoint_counts.items())]
    return {'summary': {'totalEntries': len(entries), 'validEntries': len(entries), 'malformedLinesSkipped': malformed,
            'uniqueIPs': len(by_ip), 'findings': len(findings), 'suspiciousIPs': suspicious,
            'firstSeen': overall_first['timestamp'], 'lastSeen': overall_last['timestamp']},
            'supported': {'portScan': False, 'reason': 'Access logs do not contain destination-port fields.'},
            'findings': findings, 'endpoints': endpoints, 'ips': ip_reports}
