# LinEnum
For more information visit www.rebootuser.com

Note: Export functionality is currently in the experimental stage.

General usage:

version 1.0

OPTIONS:
* -q	Quiet mode
* -C	Disable colored output
* -s 	Supply user password for sudo checks (INSECURE)
* -t	Include thorough (lengthy) tests
* -k	Enter keyword
* -r	Enter report name
* -e	Enter export location
* -h	Displays this help text

Running with no options = limited scans/no output file

EXAMPLE:
    ./LinEnum.sh -t -k password -r report -e /tmp/

* -s Use the current user with supplied password to check for sudo permissions - note this is insecure and only really for CTF use!
* -t Performs thorough (slow) tests. Without this switch default 'quick' scans are performed.
* -k An optional switch for which the user can search for a single keyword within many files (documented below).
* -r Requires the user to enter a report name. The report (.txt file) will be saved to the current working directory.
* -e Requires the user to enter an output location i.e. /tmp/export. If this location does not exist, it will be created.

See CHANGELOG.md for further details

High-level summary of the checks/tasks performed by LinEnum:

* Kernel and distribution release details
  * Quick lookup for kernel vulnerabilities (thanks to https://github.com/lucyoa/kernel-exploits)
* System Information:
  * Hostname
  * Disk, Memory, CPU, Printers
  * Networking details:
  * Current IP
  * Default route details
  * DNS server information
* User Information:
  * Current user details
  * Last logged on users
  * Show users logged onto the host
  * List all users including uid/gid information
  * List root accounts
  * Extract password policies and hash storage method information
  * Check umask value
  * Check if password hashes are stored in /etc/passwd
  * Extract full details for ‘default’ uid’s such as 0, 1000, 1001 etc
  * Attempt to read restricted files i.e. /etc/shadow
  * List current users history files (i.e .bash_history, .nano_history etc.)
  * Basic SSH checks
* Privileged access:
  * Which users have recently used sudo?
  * Determine if /etc/sudoers is accessible (executes common checks on it like LD_PRELOAD, NOPASSWD, etc.)
  * Determine if the current user has Sudo access without a password
  * Are known ‘good’ breakout binaries available via Sudo (i.e. nmap, vim etc.)
  * Is root’s home directory accessible
  * List permissions for /home/
* Environmental:
  * Display current $PATH
  * Display env information
  * Check for in-memory passwords
* Jobs/Tasks:
  * List all cron jobs
  * Locate all world-writable cron jobs
  * Locate cron jobs owned by other users of the system
  * List the active and inactive systemd timers
* Services:
  * List network connections (TCP & UDP)
  * List running processes
  * Lookup and list process binaries and associated permissions
  * List inetd.conf/xined.conf contents and associated binary file permissions
  * List init.d binary permissions
* Version Information (of the following):
  * Sudo
  * Exim4
  * MYSQL
  * Postgres
  * Apache
    * Checks user config
    * Shows enabled modules
    * Checks for htpasswd files
    * View www directories
* Default/Weak Credentials:
  * Checks for default/weak Postgres accounts
  * Checks for default/weak MYSQL accounts
* Searches:
  * Locate all SUID/GUID files
  * Locate all world-writable SUID/GUID files
  * Locate all SUID/GUID files owned by root
  * Locate ‘interesting’ SUID/GUID files (i.e. nmap, vim etc)
  * Locate files with POSIX capabilities
  * List all world-writable files
  * Find/list all accessible *.plan files and display contents
  * Find/list all accessible *.rhosts files and display contents
  * Show NFS server details (check for no_root_squash)
  * Locate *.conf*, *.cnf* and *.log* files containing keyword supplied at script runtime
  * List all *.conf files located in /etc
  * bakup (*.bak, *.old, *.tmp, *.temp, *.001, *~) files search
  * Locate mail
* Platform/software specific tests:
  * Checks to determine if we're in a Docker container
  * Checks to see if the host has Docker installed
  * Checks to determine if we're in an LXC container
