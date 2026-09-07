import re

def detect_failed_logins(sample_logs):
    pattern = re.compile(r"User: (?P<user>\w+).*?EventCode: (?P<eventcode>\d+)")
    counts = {}
    for line in sample_logs:
        match = pattern.search(line)
        print(f'RAW: {line.strip()} | MATCHED: {bool(match)}')
        if match:
            user = match.group('user')
            code = match.group('eventcode')
            if code == '4625':
                if user not in counts:
                    counts[user] = 1
                else:
                    counts[user] = counts[user] + 1
            print(f"User: {user}, EventCode: {code}, Count: {counts.get(user, 0)}")

    for user, count in counts.items():
        if count >= 3:
            print(f"ALERT: {user} failed login {count} times")

    return counts
with open('sample_logs.txt', 'r') as f:
    lines = f.readlines()
    print(f'Total lines read: {len(lines)}')
results = detect_failed_logins(lines)
print (results)
