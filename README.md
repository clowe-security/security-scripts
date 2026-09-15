# security-scripts

Standalone Python scripts for analyzing authentication logs and detecting brute-force patterns.

## Scripts

**failed_login_detector.py** — Parses Windows-style log lines for EventCode 4625 (failed logon) and flags any user account with 3+ failures.

**ssh_failed_login_detector.py** — Parses SSH auth logs and flags any source IP with 3+ failed login attempts. Tracks every distinct username attempted per IP, since multiple usernames from one IP is a stronger signal of credential stuffing than a single user mistyping a password.

Run it with:

python3 ssh_failed_login_detector.py <path_to_logfile>


## Tests

`test_ssh_failed_login_detector.py` covers the threshold-detection logic. 

Run with:

python3 test_ssh_failed_login_detector.py