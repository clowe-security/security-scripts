"""
Purpose: Flags source IPs with 3 or more failed SSH login attempts,
a common indicator of brute-force activity — especially notable
when multiple different usernames are targeted from the same IP,
which suggests credential stuffing rather than one user mistyping
a password.

Input: A list of raw SSH auth log lines (currently read from a
hardcoded file, ssh_logs.txt), each expected to contain a login
status ("Failed" or "Accepted"), a username following "for", and
a source IP following "from".

Logic: A single regex, compiled once, extracts three named groups
per line: login status, username, and source IP. Only lines where
the status is "Failed" are counted; "Accepted" (successful) logins
are ignored entirely and never touch the counts dictionary. Each
qualifying IP's count is initialized to 1 the first time it's seen,
or incremented by 1 on every subsequent failure from that IP.

Output: Prints an ALERT line for every IP whose failure count
reaches 3 or more. Also returns a dictionary mapping every IP with
at least one failure to its total count, including IPs that never
crossed the alert threshold.
"""

import re
def ssh_failed_login_detector(ssh_logs):
    pattern = re.compile(r']: (?P<login>\w+).*?for (?P<user>\w+).*?from (?P<ip>\d+\.\d+\.\d+\.\d+)')
    counts = {}

    for line in ssh_logs:
        match = pattern.search(line)

        if match:
            login = match.group('login')
            user = match.group('user')
            ip = match.group('ip')

            if login == 'Failed':
                if ip not in counts:
                    counts[ip] = 1
                else:
                    counts[ip] = counts[ip] + 1

    for ip, count in counts.items():
        if count >=3:
            print(f'ALERT: {ip} failed to login {count} times!') 

    return counts

with open('ssh_logs.txt', 'r') as f:
    lines = f.readlines()
results = ssh_failed_login_detector(lines)
print(results)               