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
    """ crack_key() -- Launches a wordlist attack against SSH key

    Args:
        keyfile (str)  - Path to SSH private key.
        wordlist (str) - Path to wordlist.

    Returns:
        True if the password has been discovered.
        False if the password has not been discovered.
    """
    with open(wordlist) as passwords:
        for password in passwords:
            password = password.rstrip()
            if not password:
                continue

            result = try_key(keyfile, password)
            if type(result) == str:
                print "      [+] Success! %s:%s" % (keyfile, result)
                return True

    print "      [-] Unable to crack SSH key with supplied wordlist."
    return False


def try_key(keyfile, password=None):
    """ try_key() -- Tries to use an SSH key.

    Args:
        keyfile (str)  - Path to SSH private key
        password (str) - Password to attempt. Default None.

    Returns:
        True if it is a valid key, but the wrong password was supplied.
        False if it is not a valid key.
        The password if it is a valid key and password.
    """
    ssh_key_types = [paramiko.RSAKey.from_private_key_file,
                     paramiko.DSSKey.from_private_key_file,
                     paramiko.ECDSAKey.from_private_key_file]

    for key_type in ssh_key_types:
        try:
            key_type(keyfile, password=password)
        except paramiko.ssh_exception.PasswordRequiredException:
            # Valid key, but wrong password
            return True
        except paramiko.ssh_exception.SSHException:
            return False
        return password

    return False


def process_key(keyfile):
    """ docstring
    """
    result = try_key(keyfile)

    if result == True:
        print "  [+] %s appears to be a valid key" % keyfile
        print "    [*] Attempting to crack.."
        # TODO add flag to skip cracking
        crack_key(keyfile, WORDLIST)
    elif result == False:
        return False
    elif result == None:
        print "  [+] %s appears to be a valid, passwordless key" % keyfile
        return True

    return True


def main():
    """ main() -- entry point of program

    Args:
        None

    Returns:
        os.EX_OK on successful run
        os_EX_USAGE on failed run
    """
    print "[+] Searching for SSH keys.."
    print

    for pwent in pwd.getpwall():
        user = pwent[0]
        sshdir = os.path.join(os.path.expanduser("~%s" % user), ".ssh")

        if os.path.isdir(sshdir):
            print "[*] Found .ssh directory for user %s: %s" % (user, sshdir)
            for root, _, filenames in os.walk(sshdir):
                for filename in filenames:
                    checkfile = os.path.join(root, filename)
                    process_key(checkfile)

    print
    print "[+] You must defeat Sheng Long to stand a chance."
    print "[+] Done."
    return os.EX_OK


if __name__ == "__main__":
    exit(main())
