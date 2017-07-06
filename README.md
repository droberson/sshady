# sshady

This tool searches for users .ssh directories, attempting to find keys
with weak passphrases or no passphrase at all. This information can be
used in a few ways:

- As a security tool, ran from cron at set intervals to alert systems
  administrators of users with weak keys.

- Offensively to check if the user has installed these weak keys
  elsewhere. A good place to look would be their shell's history file.

This tool is currently under development and probably is terrible!

To use this, you must install paramiko via pip or your OS's packaging
system:

	$ pip install paramiko
	$ sudo apt install python-paramiko

## Example output:

```
[+] Searching for SSH keys..

[*] Found .ssh directory for user daniel: /home/daniel/.ssh
  [+] /home/daniel/.ssh/id_rsa appears to be a valid key
    [*] Attempting to crack..
      [-] Unable to crack SSH key with supplied wordlist.
  [+] /home/daniel/.ssh/key_with_shitty_password appears to be a valid key
    [*] Attempting to crack..
      [+] Success! /home/daniel/.ssh/key_with_shitty_password:123456
  [+] /home/daniel/.ssh/nagios appears to be a valid, passwordless key
  [+] /home/daniel/.ssh/password appears to be a valid key
    [*] Attempting to crack..
      [+] Success! /home/daniel/.ssh/password:password

[+] Done.
```

## Thanks

Daniel Miessler for SecLists:
https://github.com/danielmiessler/SecLists

I used the 10k most common passwords list in that repo as "words.txt"

