# LinEnum - Local Linux Enumeration & Privilege Escalation Script

      _              ______                       
     | |    (o)     |  ____|                      
     | |     _ _ __ | |__   _ __  _   _ _ __ ___  
     | |    | | `_ \|  __| | `_ \| | | | '_ ` _ \ 
     | |____| | | | | |____| | | | |_| | | | | | |
     |______|_|_| |_|______|_| |_|\__,_|_| |_| |_| v1.0

LinEnum is a shell script that when executed on a Linux host allows to enumerate local information.

[![Maintainer](https://img.shields.io/badge/maintainer-filippolauria-blue)](https://github.com/filippolauria)
[![Linux](https://svgshare.com/i/Zhy.svg)](https://www.linux.com/)
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/)

## Usage

    $ ./LinEnum.sh -h
    
      USAGE:
            ./LinEnum.sh -qCst -k <keyword> -r <report name> -h
      
      OPTIONS:
      -q    Quiet mode
      -C    Disable colored output
      -s    Supply user password for sudo checks (INSECURE)
      -t    Include thorough (lengthy) tests
      -k    Enter keyword
      -r    Enter report name
      -h    Displays this help text
      
      EXAMPLE:
            ./LinEnum.sh -t -k password -r report

Option details:
* -q Does not print script banner.
* -C Script output is not colored.
* -s Use the current user with supplied password to check for sudo permissions - note this is insecure and only really for CTF use!
* -t Performs thorough (slow) tests. Without this switch default 'quick' scans are performed.
* -k An optional switch for which the user can search for a single keyword within many files (documented below).
* -r Requires the user to enter a report name. The report (.txt file) will be saved to the current working directory.

## Checks/tasks performed by LinEnum
* System
  * Get kernel name, release, version, etc.
  * Quick lookup for kernel vulnerabilities (thanks to https://github.com/lucyoa/kernel-exploits)
  * Get linux distribution
  * Get Hostname
  * Get disks, memory and CPUs information
  * Get printer(s)
* Users/Groups
  * Get system users (including last and currently logged on users) 
  * Get system groups (highlighting *interesting groups*)
  * Look for common misconfigurations in files */etc/passwd, /etc/shadow, /etc/master.passwd,* etc.
  * Look for common **sudo** misconfigurations
    * Try to use sudo with empty/common passwords
    * Highlight binaries that can be used with sudo for privileges escalation (thanks to https://gtfobins.github.io/)
    * Highlight other common misconfigurations (read/write /etc/sudoers or /etc/sudoers.d/*, etc.)
  * Look for writable home folders (including /root)
  * Highlight SSHd common misconfigurations
  * Lengthy checks:
    * List files contained in current user home
    * Look for files that don't belong to current user but writable
    * Look for files that belong to current user
    * Look for hidden files
    * Look for world-readable files within /home directory
    * Look for ssh related files (e.g. id_rsa, id_dsa, etc.) and/or their backup files
  * Look for PGP keys
  * Look for clipboard and highlighted text
* Environment
  * List environment variables (highlight *probable* interesting variables)
  * Look for AppArmor and SeLinux presence
  * Search signature verification failed in dmesg
  * Look for grsecurity and PaX presence
  * Look for exec-shield status
  * Look for ASRL status
  * Check if running in virtual environment
  * Look for sd devices in /dev
  * Look for writable directories in the PATH variable
  * List available shells
  * Get password and storage information (from */etc/login.defs*)
  * Look for in-memory passwords
* Automated jobs/tasks
  * List all cron jobs
  * Locate all world-writable cron jobs
  * Locate cron jobs owned by other users of the system
  * List the active and inactive systemd timers
* Networking:
  * Get NIC information
  * Get ARP information
  * Get DNS information
  * Get default route
  * List TCP and UDP listening services, highlighting *localhosted services* 
* Services:
  * List running processes
  * Lookup and list process binaries and associated permissions
  * List inetd.conf/xined.conf contents and associated binary file permissions
  * List init.d binary permissions
* Installed software:
  * Apache
    * Check user config
    * Show enabled modules
    * Check for htpasswd files
    * View www directories
  * Exim4
  * FreeRADIUS
  * MySQL
    * Check for default/weak MySQL accounts
    * Attempt to retrieve information from *mysql* database
  * Postgres
    * Check for default/weak Postgres accounts
  * Redis-server
    * Check if redis is protected by password
  * Runc
  * Sudo
    * Highlight vulnerable sudo versions
* Interesting files:
  * Locate all SUID/GUID files
  * Locate all world-writable SUID/GUID files
  * Locate all SUID/GUID files owned by root
  * Locate ‘interesting’ SUID/GUID files (i.e. nmap, vim etc)
  * Locate files with POSIX capabilities
  * List all world-writable files
  * Find/list all accessible *.plan files and display contents
  * Find/list all accessible *.rhosts files and display contents
  * Look for private keys or password files
  * Look for connected NFS mounts
  * Show NFS server details (check for no_root_squash)
  * Locate *.php*, *.py*, *.conf*, *.cnf* and *.log* files containing keyword supplied at script runtime
  * List all *.conf files located in /etc
  * Check /etc/fstab and /etc/mtab for common misconfigurations
  * Check for history files (e.g. .*_history, .*-hsts, etc.)
  * Check for tmux sessions 
  * bakup (*.bak, *.old, *.tmp, *.temp, *.001, *~) files search
  * Locate mail
  * Check wifi passwords in connections files
  * Find/list interesting files modified in the last 5 minutes
  * Find/list IPs inside log files
  * Find/list emails inside log files
* Platform/software specific tests:
  * Checks to determine if we're in a Docker container
  * Checks to see if the host has Docker installed
  * Checks to determine if we're in an LXC container

## Credits
Special thanks to:
 * @rebootuser, who has maintained LinEnum up to version 0.982;
 * @federicomunari (Federico M.), who has added to LinEnum a lot of new features and security checks;
 * @CyberPingU (Matteo F.), who has started making LinEnum compatible with POSIX shells (not only Bash);
 * all people mentioned in the *CONTRIBUTORS section* and in the [CONTRIBUTORS file](CONTRIBUTORS.md).
