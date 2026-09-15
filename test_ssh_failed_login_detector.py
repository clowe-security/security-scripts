import unittest
from ssh_failed_login_detector import ssh_failed_login_detector

class TestSSHDetector(unittest.TestCase):

    def test_three_failed_login_below_threshold(self):
        logs = ["Sep 4 08:14:31 server01 sshd[1025]: Failed password for admin from 203.0.113.42 port 51444 ssh2",
        "Sep 4 08:14:22 server01 sshd[1023]: Failed password for root from 203.0.113.42 port 51442 ssh2",
        "Sep 4 08:14:26 server01 sshd[1024]: Failed password for root from 203.0.113.42 port 51443 ssh2"]
        result = ssh_failed_login_detector(logs)
        self.assertEqual(result, {'203.0.113.42': {'count': 3, 'users': {'admin', 'root'}}})

if __name__ == '__main__':
    unittest.main()