"""
Purpose: Flags users with 3 or more failed login attempts, a common
indicator of brute-force login activity.

Input: A list of raw log lines (currently read from a hardcoded file,
sample_logs.txt), each expected to contain "User: <name>" and
"EventCode: <code>" somewhere in the line.

Logic: A regex pattern with named groups (user, eventcode) is
compiled once, then used to search each line individually inside the
loop. When a line's eventcode is '4625' (failed logon), that user's
count is initialized to 1 if they haven't been seen before, or
incremented by 1 if they have. Any other eventcode is ignored.

Output: Prints an ALERT line for every user whose failure count
reaches 3 or more. Also returns a dictionary mapping every user with
at least one failure to their total count, including users who never
crossed the alert threshold.
"""

import re

def detect_failed_logins(sample_logs):
    pattern = re.compile(r"User: (?P<user>\w+).*?EventCode: (?P<eventcode>\d+)")
    counts = {}
    for line in sample_logs:
        match = pattern.search(line)
        
        if match:
            user = match.group('user')
            code = match.group('eventcode')
            if code == '4625':
                if user not in counts:
                    counts[user] = 1
                else:
                    counts[user] = counts[user] + 1

    for user, count in counts.items():
        if count >= 3:
            print(f"ALERT: {user} failed login {count} times")

    return counts
with open('sample_logs.txt', 'r') as f:
    lines = f.readlines()
results = detect_failed_logins(lines)
print (results)


