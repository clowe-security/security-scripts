"""
Purpose: Flags source IPs with 3 or more failed SSH login attempts,
a common indicator of brute-force activity — especially notable
when multiple different usernames are targeted from the same IP,
which suggests credential stuffing rather than one user mistyping
a password.

Input: A log file path passed as a required command-line argument
(e.g. `python ssh_failed_login_detector.py auth.log`). The file is
expected to contain SSH auth log lines, each with a login status
("Failed" or "Accepted"), a username following "for", and a source
IP following "from".

Logic: A single regex, compiled once, extracts three named groups
per line: login status, username, and source IP. Only lines where
the status is "Failed" are counted; "Accepted" (successful) logins
are ignored entirely and never touch the counts dictionary. Each
qualifying IP's count is initialized to 1 the first time it's seen 
or incremented by 1 on every subsequent failure from that IP. and 
a User set is created with that IP that way every user account that 
IP tries to login to is tracked with that IP.

Output: Prints an ALERT line for every IP whose failure count
reaches 3 or more and the user account(s) that IP tried to login
 under. Also returns a dictionary mapping every IP with its total 
 amount of failed logins and the user account its tried to login to 
 with including IPs that never crossed the alert threshold.
"""
import re
import argparse


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
                    counts[ip] = {'count':1, 'users': {user}}
                else:
                    counts[ip]['count'] = counts[ip]['count'] + 1
                    counts[ip]['users'].add(user)

    for ip, data in counts.items():
        if data['count'] >= 3:
            print(f'ALERT: {ip} failed to login {data["count"]} times on these user account(s) {data["users"]}!')

    return counts

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect brute-force SSH login attempts from a log file.")
    parser.add_argument("logfile", help="Path to the SSH auth log file to analyze")
    args = parser.parse_args()


    try:
        with open(args.logfile, 'r') as f:
            lines = f.readlines()
        results = ssh_failed_login_detector(lines)
        print(results)
    except FileNotFoundError:
        print('ERROR: File not found')
    except PermissionError:
        print('ERROR: You do not have permission to view this file')


