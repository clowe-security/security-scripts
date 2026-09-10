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