#!/bin/bash
#
#  LinEnum.sh - Local Linux Enumeration & Privilege Escalation Script:
#  a script to enumerate local information from a Linux host
#
#  Author: @rebootuser (up to version 0.982)
#          @filippolauria (from version 1.0)
#

# version number
version="1.0"

# colored output vars
_reset="\e[00m"
_red="\e[00;31m"
_green="\e[00;32m"
_yellow="\e[00;33m"
_purple="\e[00;35m"
_cyan="\e[00;36m"
_gray="\e[0;37m"
_color_flag="--color=always"


# util functions

# usage: render_text "category" "keyword" "value"
render_text()
{
  case "$1" in
    "info") bullet="[-]"; keyword_color="${_cyan}"; value_color="";;
    "danger") bullet="[!]"; keyword_color="${_red}"; value_color="${_yellow}";;
    "warning") bullet="[!]"; keyword_color="${_yellow}"; value_color="";;
    "success") bullet="[+]"; keyword_color="${_green}"; value_color="";;
    "hint") bullet="[*]"; keyword_color="${_purlple}"; value_color="";;
    *) bullet="[.]"; keyword_color=""; value_color="";;
  esac
  
  echo -e -n "${_gray}$bullet${_reset} ${keyword_color}$2${_reset}"
  if [ "$3" ]; then echo -e "${_gray}:${_reset}\n${value_color}$3${_reset}\n"
  else echo -e "\n"; fi
}

banner()
{
 echo -e "${_red}
#########################################################
${_reset}"

if [ -z "$quiet" ]; then
  echo -e "${_yellow}      _      _       ______                       
     | |    (_)     |  ____|                      
     | |     _ _ __ | |__   _ __  _   _ _ __ ___  
     | |    | | '_ \\|  __| | '_ \\| | | | '_ \` _ \\ 
     | |____| | | | | |____| | | | |_| | | | | | |
     |______|_|_| |_|______|_| |_|\\__,_|_| |_| |_| v${_yellow}$version${_reset}
${_reset}
  Local Linux Enumeration & Privilege Escalation Script

${_red}#########################################################${_reset}
"
fi
}

#help function
usage ()
{ 
banner
echo -e "OPTIONS:
-k	Enter keyword
-e	Enter export location
-s 	Supply user password for sudo checks (INSECURE)
-t	Include thorough (lengthy) tests
-r	Enter report name
-C	Disable colored output
-q	Hide banner
-h	Displays this help text

${_yellow}Running with no options = limited scans/no output file${_reset}

EXAMPLE:
    ./LinEnum.sh -k keyword -r report -e /tmp/ -t
${_red}
#########################################################${_reset}\n"
}

debug_info()
{
echo "[-] Debug Info" 

if [ "$keyword" ]; then 
  render_text "info" "Searching for the following keyword in conf, php, ini and log files" "$keyword"
fi

if [ "$report" ]; then 
  render_text "info" "Report name" "$report"
fi

if [ "$export" ]; then
  render_text "info" "Export location" "$export"
fi

render_text "info" "Thorough tests" "`if [ "$thorough" ]; then echo -n "Enabled"; else echo -n "Disabled"; fi`"
echo

sleep 2

if [ "$export" ]; then
  mkdir "$export" 2> /dev/null
  format=$export/LinEnum-export-`date +"%d-%m-%y"`
  mkdir "$format" 2> /dev/null
fi

if [ "$sudopass" ]; then 
  render_text "warning" "Please enter password - INSECURE - really only for CTF use!"
  read -s -r userpassword
  echo 
fi

render_text "success" "Scan started at" "`date`"
}

# useful binaries (thanks to https://gtfobins.github.io/)
binarylist='ansible-playbook\|apt-get\|apt\|ar\|aria2c\|arj\|arp\|ash\|at\|atobm\|awk\|base32\|base64\|basenc\|bash\|bpftrace\|bridge\|bundler\|busctl\|busybox\|byebug\|c89\|c99\|cancel\|capsh\|cat\|certbot\|check_by_ssh\|check_cups\|check_log\|check_memory\|check_raid\|check_ssl_cert\|check_statusfile\|chmod\|chown\|chroot\|cmp\|cobc\|column\|comm\|composer\|cowsay\|cowthink\|cp\|cpan\|cpio\|cpulimit\|crash\|crontab\|csh\|csplit\|csvtool\|cupsfilter\|curl\|cut\|dash\|date\|dd\|dialog\|diff\|dig\|dmesg\|dmidecode\|dmsetup\|dnf\|docker\|dpkg\|dvips\|easy_install\|eb\|ed\|emacs\|env\|eqn\|ex\|exiftool\|expand\|expect\|facter\|file\|find\|finger\|flock\|fmt\|fold\|ftp\|gawk\|gcc\|gdb\|gem\|genisoimage\|ghc\|ghci\|gimp\|git\|grep\|gtester\|gzip\|hd\|head\|hexdump\|highlight\|hping3\|iconv\|iftop\|install\|ionice\|ip\|irb\|jjs\|join\|journalctl\|jq\|jrunscript\|knife\|ksh\|ksshell\|latex\|ld.so\|ldconfig\|less\|ln\|loginctl\|logsave\|look\|ltrace\|lua\|lualatex\|luatex\|lwp-download\|lwp-request\|mail\|make\|man\|mawk\|more\|mount\|msgattrib\|msgcat\|msgconv\|msgfilter\|msgmerge\|msguniq\|mtr\|mv\|mysql\|nano\|nawk\|nc\|nice\|nl\|nmap\|node\|nohup\|npm\|nroff\|nsenter\|octave\|od\|openssl\|openvpn\|openvt\|paste\|pdb\|pdflatex\|pdftex\|perl\|pg\|php\|pic\|pico\|pip\|pkexec\|pkg\|pr\|pry\|psql\|puppet\|python\|rake\|readelf\|red\|redcarpet\|restic\|rev\|rlogin\|rlwrap\|rpm\|rpmquery\|rsync\|ruby\|run-mailcap\|run-parts\|rview\|rvim\|scp\|screen\|script\|sed\|service\|setarch\|sftp\|sg\|shuf\|slsh\|smbclient\|snap\|socat\|soelim\|sort\|split\|sqlite3\|ss\|ssh-keygen\|ssh-keyscan\|ssh\|start-stop-daemon\|stdbuf\|strace\|strings\|su\|sysctl\|systemctl\|systemd-resolve\|tac\|tail\|tar\|taskset\|tbl\|tclsh\|tcpdump\|tee\|telnet\|tex\|tftp\|tic\|time\|timedatectl\|timeout\|tmux\|top\|troff\|tshark\|ul\|unexpand\|uniq\|unshare\|update-alternatives\|uudecode\|uuencode\|valgrind\|vi\|view\|vigr\|vim\|vimdiff\|vipw\|virsh\|watch\|wc\|wget\|whois\|wish\|xargs\|xelatex\|xetex\|xmodmap\|xmore\|xxd\|xz\|yarn\|yelp\|yum\|zip\|zsh\|zsoelim\|zypper'

system_info()
{
echo -e "${_yellow}### SYSTEM ##############################################${_reset}" 

#basic kernel info
unameinfo=`uname -a 2> /dev/null`
if [ "$unameinfo" ]; then
  render_text "info" "Kernel information" "$unameinfo"
fi

procver=`cat /proc/version 2> /dev/null`
if [ "$procver" ]; then
  render_text "info" "Kernel information (continued)" "$procver"
fi

#search all *-release files for version info
release=`cat /etc/*-release 2> /dev/null`
if [ "$release" ]; then
  render_text "info" "Specific release information" "$release"
fi

#target hostname info
hostnamed=`hostname 2> /dev/null`
if [ "$hostnamed" ]; then
  render_text "info" "Hostname" "$hostnamed"
fi
}

user_info()
{
echo -e "${_yellow}### USER/GROUP ##########################################${_reset}" 

#current user details
currusr=`id 2> /dev/null`
if [ "$currusr" ]; then
  render_text "info" "Current user/group info" "$currusr"
fi

#last logged on user information
lastlogedonusrs=`lastlog 2> /dev/null | grep -v "Never" 2> /dev/null`
if [ "$lastlogedonusrs" ]; then
  render_text "info" "Users that have previously logged onto the system" "$lastlogedonusrs"
fi

#who else is logged on
loggedonusrs=`w 2> /dev/null`
if [ "$loggedonusrs" ]; then
  render_text "info" "Who else is logged on" "$loggedonusrs"
fi

# save all users in the users variable
users=`grep -v '^#\|^$' /etc/passwd 2> /dev/null | cut -d":" -f1 2> /dev/null`

#lists all id's and respective group(s)
grpinfo=""
for u in $users; do
  idoutput=`id $u`
  entry="${_cyan}$u${_reset}"
  
  #added by phackt - look for adm group (adapted)
  isadmin=`echo $idoutput | grep "(adm)"`
  if [ "$isadmin" ]; then entry="$entry ${_yellow}(member of adm group!)${_reset}"; fi

  entry="$entry:\n\t$idoutput"
  
  # we concatenate or init the list of processes
  if [ "$grpinfo" ]; then grpinfo="$grpinfo"$'\n'"$entry"; else grpinfo="$entry"; fi
done

if [ "$grpinfo" ]; then
  render_text "info" "Group memberships" "$grpinfo"
fi

#checks to see if any hashes are stored in /etc/passwd (deprecated *nix storage method)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2> /dev/null`
if [ "$hashesinpasswd" ]; then
  render_text "danger" "It looks like we have password hashes in /etc/passwd" "$hashesinpasswd"
fi

#contents of /etc/passwd
readpasswd=`cat /etc/passwd 2> /dev/null`
if [ "$readpasswd" ]; then
  render_text "info" "Contents of /etc/passwd" "$readpasswd"

  if [ "$export" ]; then
    mkdir $format/etc-export/ 2> /dev/null
    cp /etc/passwd $format/etc-export/passwd 2> /dev/null
  fi
fi

#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow 2> /dev/null`
if [ "$readshadow" ]; then
  render_text "danger" "We can read the shadow file" "$readshadow"
  
  if [ "$export" ]; then
    mkdir $format/etc-export/ 2> /dev/null
    cp /etc/shadow $format/etc-export/shadow 2> /dev/null
  fi
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2> /dev/null`
if [ "$readmasterpasswd" ]; then
  render_text "danger" "We can read the master.passwd file" "$readmasterpasswd"

  if [ "$export" ]; then
    mkdir $format/etc-export/ 2> /dev/null
    cp /etc/master.passwd $format/etc-export/master.passwd 2> /dev/null
  fi
fi

#all root accounts (uid 0)
superman=`grep -v '^#\|^$' /etc/passwd 2> /dev/null | awk -F':' '$3 == 0 {print $1}' 2> /dev/null`
if [ "$superman" ]; then
  render_text "warning" "Super user account(s)" "$superman"
fi

# we proceed with sudo checks, only if we can get the sudo binary path
sudobin=`which sudo`
if [ "$sudobin" ]; then

  #pull out vital sudoers info
  sudoers=`grep -v '^#\|^$' /etc/sudoers 2> /dev/null`
  if [ "$sudoers" ]; then
    render_text "warning" "Sudoers configuration (condensed)" "$sudoers"
    
    # is LD_PRELOAD explicitly defined in /etc/sudoers?
    ldpreloadsudoers=`echo "$sudoers" | grep ${_color_flag} LD_PRELOAD`
    if [ "$ldpreloadsudoers" ]; then
      render_text "danger" "LD_PRELOAD is explicitly defined in /etc/sudoers" "$ldpreloadsudoers"
    fi
    
    # check for NOPASSWD in /etc/sudoers
    nopasswdsudoers=`echo "$sudoers" | grep ${_color_flag} NOPASSWD`
    if [ "$nopasswdsudoers" ]; then
      render_text "danger" "NOPASSWD flag(s) found in /etc/sudoers" "$nopasswdsudoers"
    fi

    if [ "$export" ]; then
      mkdir $format/etc-export/ 2> /dev/null
      cp /etc/sudoers $format/etc-export/sudoers 2> /dev/null
    fi
  fi
  
  #can we sudo without supplying a password?
  sudoperms=`echo '' | sudo -S -l -k 2> /dev/null`
  if [ "$sudoperms" ]; then
    render_text "danger" "We can sudo without supplying a password" "$sudoperms"

    #known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values)
    sudopwnage=`echo "$sudoperms" | xargs -n 1 2> /dev/null | sed 's/,*$//g' 2> /dev/null | grep -w $binarylist 2> /dev/null`
    if [ "$sudopwnage" ]; then
      render_text "danger" "Possible sudo pwnage" "$sudopwnage"
    fi

  else
    
    if [ "$sudopass" ]; then
      #can we sudo when supplying a password?
      sudoauth=`echo $userpassword | sudo -S -l -k 2> /dev/null`
      if [ "$sudoauth" ]; then
        render_text "danger" "We can sudo when supplying a password" "$sudoauth"

        #known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values) - authenticated
        sudopermscheck=`echo "$sudoauth" | xargs -n 1 2> /dev/null | sed 's/,*$//g' 2> /dev/null | grep -w $binarylist 2> /dev/null`
        if [ "$sudopermscheck" ]; then
          render_text "danger" "Possible sudo pwnage" "$sudopermscheck"
        fi

      fi
      
    fi
  fi

  #who has sudoed in the past
  sudoerhomelist="`find /home -name .sudo_as_admin_successful -exec dirname {} \; 2> /dev/null | sort -u`"
  if [ "$sudoerhomelist" ]; then
    sudoerslist=""
    for h in $sudoerhomelist; do
      entry=`ls -dl "$h" 2> /dev/null | awk 'NR==1 {print $3}' 2> /dev/null`
      if [ "$sudoerslist" ]; then sudoerslist="$sudoerslist"$'\n'"$entry"; else sudoerslist="$entry"; fi
    done
    
    if [ "$sudoerslist" ]; then
        render_text "info" "Users that have recently used sudo" "$sudoerslist"
    fi
  fi

fi

#checks to see if roots home directory is accessible
rthmdir=`ls ${_color_flag} -ahl /root/ 2> /dev/null`
if [ "$rthmdir" ]; then
  render_text "danger" "We can read root's home directory" "$rthmdir"
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls ${_color_flag} -ahl /home/ 2> /dev/null`
if [ "$homedirperms" ]; then
  render_text "info" "Are permissions on /home directories lax" "$homedirperms"
fi

#is root permitted to login via ssh
sshrootlogin=`grep '^\s*PermitRootLogin\s\+' /etc/ssh/sshd_config 2> /dev/null | cut -d' ' -f2`
if [ "$sshrootlogin" = "yes" ]; then
  render_text "info" "Root is allowed to login via SSH" "${sshrootlogin}"
fi

#thorough checks
if [ "$thorough" = "1" ]; then
  current_user=`whoami`
  
  #looks for files we can write to that don't belong to us
  grfilesall=`find / -writable \! -user $current_user -type f \! \( -path "/proc/*" -o -path "/sys/*" \) 2> /dev/null | \
              xargs -r ls ${_color_flag} -lah 2> /dev/null`
  if [ "$grfilesall" ]; then
    render_text "info" "Files not owned by user but writable by group" "$grfilesall"
  fi

  #looks for files that belong to us
  ourfilesall=`find / -user $current_user -type f \! \( -path "/proc/*" -o -path "/sys/*" \) 2> /dev/null | \
               xargs -r ls ${_color_flag} -lah 2> /dev/null`
  if [ "$ourfilesall" ]; then
    render_text "info" "Files owned by our user" "$ourfilesall"
  fi

  #looks for hidden files
  hiddenfiles=`find / -name ".*" -type f \! \( -path "/proc/*" -o -path "/sys/*" \) 2> /dev/null | \
               xargs -r ls ${_color_flag} -lah 2> /dev/null`
  if [ "$hiddenfiles" ]; then
    render_text "warning" "Hidden files" "$hiddenfiles"
  fi
  
  #looks for world-reabable files within /home
  # depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
  wrfilesinhome=`find /home/ -perm -4 -type f 2> /dev/null`
  if [ "$wrfilesinhome" ]; then
    wrfilesinhomeoutput=`echo "$wrfilesinhome" | xargs -r ${_color_flag} ls -lah 2> /dev/null`
    render_text "warning" "World-readable files within /home" "$wrfilesinhomeoutput"

    if [ "$export" ]; then
      mkdir $format/wr-files/ 2> /dev/null
      for f in $wrfilesinhome; do cp --parents $f $format/wr-files/ ; done 2> /dev/null
    fi
  fi

  #lists current user's home directory contents
  current_user_homedir=`cat /etc/passwd | grep "^$current_user" | cut -d':' -f6`
  homedircontents=`ls ${_color_flag} -Rlah "$current_user_homedir" 2> /dev/null`
  if [ "$homedircontents" ] ; then
    render_text "info" "Home directory contents" "$homedircontents"
  fi

  #checks for if various ssh files (or their backups) are accessible
  # this can take some time so is only 'activated' with thorough scanning switch
  sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts*" -o -name "authorized_hosts*" -o -name "authorized_keys*" \) 2> /dev/null`

  if [ "$sshfiles" ]; then
    sshfilesoutput="`echo "$sshfiles" | xargs ls ${_color_flag} -lah 2> /dev/null`"
    render_text "danger" "SSH keys/host information found in the following locations" "$sshfiles"
    
    if [ "$export" ]; then
      mkdir $format/ssh-files/ 2> /dev/null
      for f in $sshfiles; do cp --parents $f $format/ssh-files/; done 2> /dev/null
    fi
  fi
fi
}

environmental_info()
{
echo -e "${_yellow}### ENVIRONMENTAL #######################################${_reset}" 

#env information
envinfo=`env 2> /dev/null | grep -v 'LS_COLORS' 2> /dev/null`
if [ "$envinfo" ]; then
  render_text "info" "Environment information" "$envinfo"
fi

#check if selinux is enabled
sestatus=`sestatus 2> /dev/null`
if [ "$sestatus" ]; then
  render_text "info" "SELinux seems to be present" "$sestatus"
fi

#phackt

#current path configuration
pathinfo=`echo $PATH 2> /dev/null`
if [ "$pathinfo" ]; then
  pathswriteable=`ls ${_color_flag} -dlah $(echo $PATH | tr ":" " ")`
  render_text "info" "Path information" "$pathinfo\n\n$pathswriteable"
fi

#lists available shells
shellinfo=`ls ${_color_flag} -dlah $(grep -v '^#\|^$' /etc/shells 2> /dev/null) 2> /dev/null`
if [ "$shellinfo" ]; then
  render_text "info" "Available shells as specified in /etc/shells" "$shellinfo"
fi

#current umask value with both octal and symbolic output
umaskvalue=`umask -S 2> /dev/null & umask 2> /dev/null`
if [ "$umaskvalue" ]; then
  render_text "info" "Current umask value" "$umaskvalue"
fi

#umask value as in /etc/login.defs
umaskdef=`grep ${_color_flag} -i "^UMASK" /etc/login.defs 2> /dev/null`
if [ "$umaskdef" ]; then
  render_text "info" "umask value as specified in /etc/login.defs" "$umaskdef"
fi

#password policy information as stored in /etc/login.defs
logindefs=`grep ${_color_flag} "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2> /dev/null`
if [ "$logindefs" ]; then
  render_text "info" "Password and storage information" "$logindefs"

  if [ "$export" ]; then
    mkdir $format/etc-export/ 2> /dev/null
    cp /etc/login.defs $format/etc-export/login.defs 2> /dev/null
  fi
fi

#In-memory passwords
inmemorypassword=`strings /dev/mem -n10 2> /dev/null | grep ${_color_flag} -i PASS`
if [ "$inmemorypassword" ]; then
  render_text "danger" "In-memory passwords" "$inmemorypassword"
fi
}

job_info()
{
echo -e "${_yellow}### JOBS/TASKS ##########################################${_reset}" 

#are there any cron jobs configured
cronjobs=`ls ${_color_flag} -lah /etc/cron* 2> /dev/null`
if [ "$cronjobs" ]; then
  render_text "info" "Cron jobs" "$cronjobs"
fi

#can we manipulate these jobs in any way
cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -lah {} \; -exec cat {} 2> /dev/null \;`
if [ "$cronjobwwperms" ]; then
  render_text "info" "World-writable cron jobs and file contents" "$cronjobwwperms"
fi

#contab contents
crontabvalue=`cat /etc/crontab 2> /dev/null`
if [ "$crontabvalue" ]; then
  render_text "info" "Crontab contents" "$crontabvalue"
fi

crontabvar=`ls ${_color_flag} -lah /var/spool/cron/crontabs 2> /dev/null`
if [ "$crontabvar" ]; then
  render_text "info" "Anything interesting in /var/spool/cron/crontabs" "$crontabvar"
fi

anacronjobs=`ls ${_color_flag} -lah /etc/anacrontab 2> /dev/null; cat /etc/anacrontab 2> /dev/null`
if [ "$anacronjobs" ]; then
  render_text "info" "Anacron jobs and associated file permissions" "$anacronjobs"
fi

anacrontab=`ls ${_color_flag} -lah /var/spool/anacron 2> /dev/null`
if [ "$anacrontab" ]; then
  render_text "info" "When were jobs last executed (/var/spool/anacron contents)" "$anacrontab"
fi

#see if any users have associated cronjobs (priv command)
cronother=`echo $users | xargs -n1 crontab -l -u 2> /dev/null`
if [ "$cronother" ]; then
  render_text "info" "Jobs held by all users" "$cronother"
fi

# list systemd timers
if [ "$thorough" = "1" ]; then
  # include inactive timers in thorough mode
  systemdtimers=`systemctl list-timers --all 2> /dev/null`
else
  systemdtimers=`systemctl list-timers 2> /dev/null | head -n -1 2> /dev/null`
fi

if [ "$systemdtimers" ]; then
  render_text "info" "Systemd timers" "$systemdtimers"

  if [ "$thorough" != "1" ]; then
    # replace the info in the output with a hint towards thorough mode
    render_text "hint" "Enable thorough tests to see inactive timers"
  fi
fi
}

networking_info()
{
echo -e "${_yellow}### NETWORKING  ##########################################${_reset}" 

#nic information
nicinfo=`/sbin/ifconfig -a 2> /dev/null`
if [ "$nicinfo" ]; then
  render_text "info" "Network and IP info" "$nicinfo"
else
  #nic information (using ip)
  nicinfoip=`/sbin/ip a 2> /dev/null`
  if [ "$nicinfoip" ]; then
    render_text "info" "Network and IP info" "$nicinfoip"
  fi
fi

#arp information
arpinfo=`arp -a 2> /dev/null`
if [ "$arpinfo" ]; then
  render_text "info" "ARP history" "$arpinfo"
else
  #arp information (using ip)
  arpinfoip=`ip n 2> /dev/null`
  if [ "$arpinfoip" ]; then
    render_text "info" "ARP history" "$arpinfoip"
  fi
fi

#dns settings
nsinfo=`grep ${_color_flag} "nameserver" /etc/resolv.conf 2> /dev/null`
if [ "$nsinfo" ]; then
  render_text "info" "Nameserver(s)" "$nsinfo"
fi

nsinfosysd=`systemd-resolve --status 2> /dev/null`
if [ "$nsinfosysd" ]; then
  render_text "info" "Nameserver(s)" "$nsinfosysd"
fi

#default route configuration
defroute=`route 2> /dev/null | grep ${_color_flag} default`
if [ "$defroute" ]; then
  render_text "info" "Default route" "$defroute"
else
  #default route configuration (using ip)
  defrouteip=`ip r 2> /dev/null | grep ${_color_flag} default`
  if [ "$defrouteip" ]; then
    render_text "info" "Default route" "$defrouteip"
  fi
fi

#listening TCP
tcpservs=`netstat -lntp 2> /dev/null`
if [ "$tcpservs" ]; then
  render_text "info" "Listening TCP" "$tcpservs"
else
  #listening TCP (using ss)
  tcpservsip=`ss -lntp 2> /dev/null`
  if [ "$tcpservsip" ]; then
    render_text "info" "Listening TCP" "$tcpservsip"
  fi
fi

#listening UDP
udpservs=`netstat -lnup 2> /dev/null`
if [ "$udpservs" ]; then
  render_text "info" "Listening UDP" "$udpservs"
else
  #listening UDP (using ss)
  udpservsip=`ss -lnup 2> /dev/null`
  if [ "$udpservsip" ]; then
    render_text "info" "Listening UDP" "$udpservsip"
  fi
fi
}

services_info()
{
echo -e "${_yellow}### SERVICES #############################################${_reset}" 

#running processes
psaux=`ps aux 2> /dev/null`
if [ "$psaux" ]; then
  render_text "info" "Running processes" "$psaux"
fi

#lookup process binary path and permissisons
proclist=`ps -eo command | grep -v "^\(\[\|COMMAND\|(\)" | awk '{print $1}' | awk '!x[$0]++' | xargs -r which -- 2> /dev/null`
if [ "$proclist" ]; then
  proclistoutput=`echo "$proclist" | xargs -r ls ${_color_flag} -lah 2> /dev/null`
  render_text "info" "Process binaries and associated permissions (from the above list)" "$proclistoutput"

  if [ "$export" ]; then
    mkdir $format/ps-export/ 2> /dev/null
    for binary in $proclist; do cp --parents $binary $format/ps-export/; done 2> /dev/null
  fi
fi

#anything 'useful' in inetd.conf
inetdread=`grep -v '^#\|^$' /etc/inetd.conf 2> /dev/null`
if [ "$inetdread" ]; then
  render_text "info" "Contents of /etc/inetd.conf (condensed)" "$inetdread"

  if [ "$export" ]; then
    mkdir $format/etc-export/ 2> /dev/null
    cp /etc/inetd.conf $format/etc-export/inetd.conf 2> /dev/null
  fi
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`awk '{print $7}' /etc/inetd.conf 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
if [ "$inetdbinperms" ]; then
  render_text "info" "The related inetd binary permissions" "$inetdbinperms"
fi

#check /etc/xinetd.conf file content
xinetdread=`cat /etc/xinetd.conf 2> /dev/null`
if [ "$xinetdread" ]; then
  render_text "info" "Contents of /etc/xinetd.conf" "$xinetdread"
  
  if [ "$export" ]; then
    mkdir $format/etc-export/ 2> /dev/null
    cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2> /dev/null
  fi
fi

#check /etc/xinetd.d directory content
xinetdincd=`grep ${_color_flag} "/etc/xinetd.d" /etc/xinetd.conf 2> /dev/null`
if [ "$xinetdincd" ]; then
  render_text "info" "/etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below" "`ls ${_color_flag} -lah /etc/xinetd.d 2> /dev/null`"
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`awk '{print $7}' /etc/xinetd.conf 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
if [ "$xinetdbinperms" ]; then
  render_text "info" "The related xinetd binary permissions" "$xinetdbinperms"
fi

initdread=`ls ${_color_flag} -lah /etc/init.d 2> /dev/null`
if [ "$initdread" ]; then
  render_text "info" "/etc/init.d/ binary permissions" "$initdread"
fi

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
if [ "$initdperms" ]; then
  render_text "info" "/etc/init.d/ files not belonging to root" "$initdperms"
fi

rcdread=`ls ${_color_flag} -la /etc/rc.d/init.d 2> /dev/null`
if [ "$rcdread" ]; then
  render_text "info" "/etc/rc.d/init.d binary permissions" "$rcdread"
fi

#init.d files NOT belonging to root!
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
if [ "$rcdperms" ]; then
  render_text "danger" "/etc/rc.d/init.d files not belonging to root" "$rcdperms"
fi

usrrcdread=`ls ${_color_flag} -lah /usr/local/etc/rc.d 2> /dev/null`
if [ "$usrrcdread" ]; then
  render_text "info" "/usr/local/etc/rc.d binary permissions" "$usrrcdread"
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
if [ "$usrrcdperms" ]; then
  render_text "danger" "/usr/local/etc/rc.d files not belonging to root" "$usrrcdperms"
fi

initread=`ls ${_color_flag} -la /etc/init/ 2> /dev/null`
if [ "$initread" ]; then
  render_text "info" "/etc/init/ config file permissions" "$initread"
fi

# upstart scripts not belonging to root
initperms=`find /etc/init \! -uid 0 -type f 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
if [ "$initperms" ]; then
   render_text "danger" "/etc/init/ config files not belonging to root" "$initperms"
fi

if [ "$thorough" = "1" ]; then systemdread=`ls ${_color_flag} -lthR /lib/systemd/ /etc/systemd/ 2> /dev/null`;
else systemdread="`find /lib/systemd/ /etc/systemd/ -name *.service -type f 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`"; fi
if [ "$systemdread" ]; then
  render_text "info" "systemd config file permissions" "$systemdread"
fi

# systemd files not belonging to root
systemdperms=`find /lib/systemd/ /etc/systemd/ \! -uid 0 -type f 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
if [ "$systemdperms" ]; then
   render_text "danger" "systemd config files not belonging to root" "$systemdperms"
fi
}

software_configs()
{
echo -e "${_yellow}### SOFTWARE #############################################${_reset}" 

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`sudo -V 2> /dev/null | grep "Sudo version" | cut -d" " -f3`
if [ "$sudover" ]; then
  render_text "info" "Sudo version" "$sudover"
fi

#mysql details - if installed
mysqlver=`mysql --version 2> /dev/null`
if [ "$mysqlver" ]; then
  render_text "info" "MYSQL version" "$mysqlver"
fi

#checks to see if root/root will get us a connection
mysqlconnect=`mysqladmin -uroot -proot version 2> /dev/null`
if [ "$mysqlconnect" ]; then
  render_text "danger" "We can connect to the local MYSQL service with default root/root credentials" "$mysqlconnect"
fi

#mysql version details
mysqlconnectnopass=`mysqladmin -uroot version 2> /dev/null`
if [ "$mysqlconnectnopass" ]; then
  render_text "danger" "We can connect to the local MYSQL service as 'root' and without a password" "$mysqlconnectnopass"
fi

#postgres details - if installed
postgver=`psql -V 2> /dev/null`
if [ "$postgver" ]; then
  render_text "info" "Postgres version" "$postgver"
fi

#checks to see if any postgres password exists and connects to DB 'template'
psql_default_users="postgres pgsql"
for u in $psql_default_users; do
  for i in {0..9}; do
    w="template$i"
    postcon=`psql -U $u -w $w -c 'select version()' 2> /dev/null | grep ${_color_flag} version`

    if [ "$postcon" ]; then
      render_text "danger" "We can connect to Postgres DB $w as user $u with no password" "$postcon"
    fi
    
  done
done

#apache details - if installed
apachever=`apache2 -v 2> /dev/null; httpd -v 2> /dev/null`
if [ "$apachever" ]; then
  render_text "info" "Apache version" "$apachever"
  echo -e "\n"
fi

#what account is apache running under
apacheusr=`grep -i 'user\|group' /etc/apache2/envvars 2> /dev/null | awk '{sub(/.*\export /,"")}1' 2> /dev/null`
if [ "$apacheusr" ]; then
  render_text "info" "Apache user configuration:${_reset}" "$apacheusr"

  if [ "$export" ]; then
    mkdir --parents $format/etc-export/apache2/ 2> /dev/null
    cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2> /dev/null
  fi
fi

#installed apache modules
apachemodules=`apache2ctl -M 2> /dev/null; httpd -M 2> /dev/null`
if [ "$apachemodules" ]; then
  render_text "info" "Installed Apache modules" "$apachemodules"
fi

#htpasswd check
htpasswd=`find / -name .htpasswd* -print -exec cat {} \; 2> /dev/null`
if [ "$htpasswd" ]; then
    render_text "danger" ".htpasswd found - could contain passwords" "$htpasswd"
fi

#anything in the default http home dirs (a thorough only check as output can be large)
if [ "$thorough" = "1" ]; then
  apache_dirs="/var/www/ /srv/www/htdocs/ /usr/local/www/apache2/data/ /opt/lampp/htdocs/"
  apachehomedirs=`ls ${_color_flag} -Rlah $d 2> /dev/null`
  if [ "$apachehomedirs" ]; then
    render_text "info" "Apache2 home dir contents" "$apachehomedirs"
  fi
fi

}

interesting_files()
{
echo -e "${_yellow}### INTERESTING FILES ####################################${_reset}" 

#checks to see if various files are installed
bin_of_interest="nc netcat socat wget nmap gcc curl"
bin_fullpath=`echo "$bin_of_interest" | xargs -r which -- 2> /dev/null`
if [ "$bin_fullpath" ]; then
  render_text "info" "Useful file locations" "$bin_fullpath"
fi

#limited search for installed compilers
compiler=`dpkg --list 2> /dev/null | grep compiler | grep -v decompiler 2> /dev/null && yum list installed 'gcc*' 2> /dev/null| grep gcc 2> /dev/null`
if [ "$compiler" ]; then
  render_text "info" "Installed compilers" "$compiler"
  echo -e "\n"
fi

#manual check - lists out sensitive files, can we read/modify etc.
sensitive_files="/etc/passwd /etc/group /etc/profile /etc/shadow /etc/master.passwd /etc/security/opasswd"
render_text "warning" "Can we read/write sensitive files" "`ls ${_color_flag} -lah $sensitive_files 2> /dev/null`"

#files that have changed in the last 10 minutes
changedfiles=`find / -mmin 10 2> /dev/null | grep -v "^/proc" | xargs -r ls ${_color_flag} -dlah 2> /dev/null`
if [ "$changedfiles"]; then
  render_text "warning" "Files that have changed in the last 10 minutes" "$changedfiles"
fi

#search for suid files
allsuid=`find / -perm -4000 -type f 2> /dev/null`
if [ "$allsuid" ]; then
  allsuiddetails=`echo "$allsuid" | xargs -r ls ${_color_flag} -lah 2> /dev/null`
  if [ "$allsuiddetails" ]; then
    render_text "info" "SUID files" "$allsuiddetails"
  fi

  #list of 'interesting' suid files - feel free to make additions
  interestingsuid=`echo "$allsuiddetails" | grep -w $binarylist 2> /dev/null`
  if [ "$interestingsuid" ]; then
    render_text "warning" "Possibly interesting SUID files" "$interestingsuid"
  fi

  #lists world-writable suid files
  wwsuid=`find $allsuid \! -uid 0 -perm -4002 -type f 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
  if [ "$wwsuid" ]; then
    render_text "warning" "World-writable SUID files" "$wwsuid"
  fi

  #lists world-writable suid files owned by root
  wwrootsuid=`find $allsuid -uid 0 -perm -4002 -type f 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
  if [ "$wwrootsuid" ]; then
    render_text "warning" "World-writable SUID files owned by root" "$wwrootsuid"
  fi

  if [ "$export" ]; then
    mkdir $format/suid-files/ 2> /dev/null
    for f in $allsuid; do cp $f $format/suid-files/; done 2> /dev/null
  fi
fi

#search for sgid files
allsgid=`find / -perm -2000 -type f 2> /dev/null`
if [ "$allsgid" ]; then
  allsgiddetails=`echo "$allsgid" | xargs -r ls ${_color_flag} -lah 2> /dev/null`
  if [ "$allsgiddetails" ]; then
    render_text "info" "SGID files" "$allsgiddetails"
  fi
  
  #list of 'interesting' sgid files
  interestingsgid=`echo "$allsgiddetails" | grep -w $binarylist 2> /dev/null`
  if [ "$interestingsgid" ]; then
    render_text "warning" "Possibly interesting SGID files" "$interestingsgid"
  fi

  #lists world-writable sgid files
  wwsgid=`find $allsgid \! -uid 0 -perm -2002 -type f 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
  if [ "$wwsgid" ]; then
    render_text "warning" "World-writable SGID files" "$wwsgid"
  fi

  #lists world-writable sgid files owned by root
  wwrootsgid=`find $allsgid -uid 0 -perm -2002 -type f 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
  if [ "$wwrootsgid" ]; then
    render_text "warning" "World-writable SGID files owned by root" "$wwrootsgid"
  fi
  
  if [ "$export" ]; then
    mkdir $format/sgid-files/ 2> /dev/null
    for f in $allsgid; do cp $f $format/sgid-files/; done 2> /dev/null
  fi
fi

#list all files with POSIX capabilities set along with there capabilities
fileswithcaps=`getcap -r / 2> /dev/null || /sbin/getcap -r / 2> /dev/null`
if [ "$fileswithcaps" ]; then
  render_text "info" "Files with POSIX capabilities set" "$fileswithcaps"
  
  if [ "$export" ]; then
    mkdir $format/files_with_capabilities/ 2> /dev/null
    for i in $fileswithcaps; do cp $i $format/files_with_capabilities/; done 2> /dev/null
  fi
fi

#searches /etc/security/capability.conf for users associated capapilies
userswithcaps=`grep -v '^#\|none\|^$' /etc/security/capability.conf 2> /dev/null`
if [ "$userswithcaps" ]; then
  render_text "info" "Users with specific POSIX capabilities" "$userswithcaps"

  #matches the capabilities found associated with users with the current user
  matchedcaps=`echo -e "$userswithcaps" | grep \`whoami\` | awk '{print $1}' 2> /dev/null`
  if [ "$matchedcaps" ]; then
    render_text "info" "Capabilities associated with the current user" "$matchedcaps"

    #matches the files with capapbilities with capabilities associated with the current user
    matchedfiles=`echo -e "$matchedcaps" | while read -r cap; do echo -e "$fileswithcaps" | grep "$cap"; done 2> /dev/null`
    if [ "$matchedfiles" ]; then
      render_text "warning" "Files with the same capabilities associated with the current user (You may want to try abusing those capabilties)" "$matchedfiles"
      
      #lists the permissions of the files having the same capabilies associated with the current user
      matchedfilesperms=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do ls ${_color_flag} -lah $f; done 2> /dev/null`
      render_text "info" "Permissions of files with the same capabilities associated with the current user" "$matchedfilesperms"
      
      if [ "$matchedfilesperms" ]; then
        #checks if any of the files with same capabilities associated with the current user is writable
        writablematchedfiles=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do find $f -writable -exec ls -la {} \; 2> /dev/null; done`
        if [ "$writablematchedfiles" ]; then
          render_text "info" "User/Group writable files with the same capabilities associated with the current user" "$writablematchedfiles"
        fi
      fi
    fi
  fi
fi

if [ "$thorough" = "1" ]; then

  #look for private keys - thanks djhohnstein
  privatekeyfiles=`grep ${_color_flag} -rl "PRIVATE KEY-----" /home 2> /dev/null`
  if [ "$privatekeyfiles" ]; then
    render_text "danger" "Private SSH keys found" "$privatekeyfiles"
  fi

  #look for AWS keys - thanks djhohnstein
  awskeyfiles=`grep ${_color_flag} -rli "aws_secret_access_key" /home 2> /dev/null`
  if [ "$awskeyfiles" ]; then
    render_text "danger" "AWS secret keys found" "$awskeyfiles"
  fi

  #look for git credential files - thanks djhohnstein
  gitcredfiles=`find / -name ".git-credentials*" 2> /dev/null`
  if [ "$gitcredfiles" ]; then
    render_text "danger" "Git credentials saved on the machine" "$gitcredfiles"
  fi

  #list all world-writable files excluding /proc and /sys
  wwfiles=`find / \! \( -path "*/proc/*" -o -path "/sys/*" \) -perm -2 -type f -exec ls -lah {} \; 2> /dev/null`
  if [ "$wwfiles" ]; then
    render_text "info" "World-writable files (excluding /proc and /sys)" "$wwfiles"

    if [ "$export" ]; then
      mkdir $format/ww-files/ 2> /dev/null
      for f in $wwfiles; do cp --parents $f $format/ww-files/; done 2> /dev/null
	fi
  fi

fi

#are any .plan files accessible in /home (could contain useful information)
usrplan=`find /home /usr/home -iname *.plan -exec ls -lah {} \; -exec cat {} \; 2> /dev/null`
if [ "$usrplan" ]; then
  render_text "warning" "Plan file permissions and contents" "$usrplan"

  if [ "$export" ]; then
    mkdir $format/plan_files/ 2> /dev/null
    for f in $usrplan; do cp --parents $f $format/plan_files/; done 2> /dev/null
  fi
fi

#are there any .rhosts files accessible - these may allow us to login as another user etc.
rhostsusr=`find /home /usr/home -iname *.rhosts -exec ls -lah {} 2> /dev/null \; -exec cat {} \; 2> /dev/null`
if [ "$rhostsusr" ]; then
  render_text "warning" "rhost config file(s) and file contents" "$rhostsusr"

  if [ "$export" ]; then
    mkdir $format/rhosts/ 2> /dev/null
    for i in $rhostsusr; do cp --parents $i $format/rhosts/; done 2> /dev/null
  fi
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -lah {} 2> /dev/null \; -exec cat {} \; 2> /dev/null`
if [ "$rhostssys" ]; then
  render_text "info" "hosts.equiv file and contents" "$rhostssys"

  if [ "$export" ]; then
    mkdir $format/rhosts/ 2> /dev/null
    for f in $rhostssys; do cp --parents $f $format/rhosts/; done 2> /dev/null
  fi
fi

#list nfs shares/permisisons etc.
nfsexports=`ls ${_color_flag} -lah /etc/exports 2> /dev/null; cat /etc/exports 2> /dev/null`
if [ "$nfsexports" ]; then
  render_text "warning" "NFS config details" "$nfsexports"

  # check for no_root_squash in /etc/exports
  no_root_squash=`echo "$nfsexports" | grep ${_color_flag} no_root_squash`
  if [ "$no_root_squash" ]; then
    render_text "danger" "no_root_squash found in /etc/exports" "$no_root_squash"
  fi

  if [ "$export" ]; then
    mkdir $format/etc-export/ 2> /dev/null
    cp /etc/exports $format/etc-export/exports 2> /dev/null
  fi
fi

if [ "$thorough" = "1" ]; then
  #phackt
  #displaying /etc/fstab
  fstab=`cat /etc/fstab 2> /dev/null`
  if [ "$fstab" ]; then
    render_text "info" "NFS displaying partitions and filesystems - you need to look for exotic filesystems" "$fstab"
  fi
fi

#looking for credentials in /etc/fstab
fstab=`grep username /etc/fstab 2> /dev/null | awk '{sub(/.*\username=/,""); sub(/\,.*/,"")}1' 2> /dev/null | \
       xargs -r echo username: 2> /dev/null; grep password /etc/fstab 2> /dev/null | awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2> /dev/null | \
       xargs -r echo password: 2> /dev/null; grep domain /etc/fstab 2> /dev/null | awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2> /dev/null | \
       xargs -r echo domain: 2> /dev/null`
if [ "$fstab" ]; then
  render_text "danger" "Looks like there are credentials in /etc/fstab" "$fstab"

  if [ "$export" ]; then
    mkdir $format/etc-exports/ 2> /dev/null
    cp /etc/fstab $format/etc-exports/fstab done 2> /dev/null
  fi
fi

fstabcred=`grep cred /etc/fstab 2> /dev/null | awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2> /dev/null | \
           xargs -I{} sh -c 'ls ${_color_flag} -lah {}; cat {}' 2> /dev/null`
if [ "$fstabcred" ]; then
  render_text "danger" "/etc/fstab contains a credentials file" "$fstabcred"
  
  if [ "$export" ] && [ "$fstabcred" ]; then
    mkdir $format/etc-exports/ 2> /dev/null
    cp /etc/fstab $format/etc-exports/fstab done 2> /dev/null
  fi
fi

#can we read some log?
readablelogs=`find /etc/log /var/log -type f -name *log* -readable 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
if [ "$readablelogs" ]; then
  render_text "warning" "We can read these log files content" "$readablelogs"
fi

if [ "$keyword" ]; then
  #use supplied keyword and cat *.conf files for potential matches - output will show line number within relevant file path where a match has been located
  confkeyfiles=`find / -maxdepth 4 \( -name *.conf* -o -name *.cnf* -a \! -name *example \) -type f 2> /dev/null`
  if [ "$confkeyfiles" ]; then
    confkey=`echo "$confkeyfiles" | xargs grep -Hn $keyword 2> /dev/null`
    if [ "$confkey" ]; then
      render_text "warning" "Find keyword ($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears)" "$confkey"
    
      if [ "$export" ]; then
        mkdir --parents $format/keyword_file_matches/config_files/ 2> /dev/null
        for f in $confkeyfiles; do cp --parents $f $format/keyword_file_matches/config_files/; done 2> /dev/null
      fi
    fi
  fi

  #use supplied keyword and cat *.php files for potential matches - output will show line number within relevant file path where a match has been located
  phpkeyfiles=`find / -maxdepth 10 -name *.php* -type f 2> /dev/null`
  if [ "$phpkeyfiles" ]; then
    phpkey=`echo "$phpkeyfiles" | xargs grep -Hn $keyword 2> /dev/null`
    if [ "$phpkey" ]; then
      render_text "warning" "Find keyword ($keyword) in .php files (recursive 10 levels - output format filepath:identified line number where keyword appears)" "$phpkey"
      
      if [ "$export" ]; then
        mkdir --parents $format/keyword_file_matches/php_files/ 2> /dev/null
        for f in $phpkeyfiles; do cp --parents $f $format/keyword_file_matches/php_files/; done 2> /dev/null
      fi
    fi
  fi

  #use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
  logkeyfiles=`find / -maxdepth 4 -name *.log* -type f 2> /dev/null`
  if [ "$logkeyfiles" ]; then
    logkey=`echo "$logkeyfiles" | xargs grep -Hn $keyword 2> /dev/null`
    if [ "$logkey" ]; then
      render_text "warning" "Find keyword ($keyword) in .log files (recursive 4 levels - output format filepath:identified line number where keyword appears)" "$logkey"

      if [ "$export" ]; then
        mkdir --parents $format/keyword_file_matches/log_files/ 2> /dev/null
        for f in $logkeyfiles; do cp --parents $f $format/keyword_file_matches/log_files/; done 2> /dev/null
      fi
    fi
  fi

  #use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
  inikeyfiles=`find / -maxdepth 4 -name *.ini -type f 2> /dev/null`
  if [ "$inikeyfiles" ]; then
    inikey=`echo "$inikeyfiles" | xargs grep -Hn $keyword 2> /dev/null`
    if [ "$inikey" ]; then
      render_text "warning" "Find keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears)" "$inikey"

      if [ "$export" ]; then
	    mkdir --parents $format/keyword_file_matches/ini_files/ 2> /dev/null
        for f in $inikeyfiles; do cp --parents $f $format/keyword_file_matches/ini_files/; done 2> /dev/null
      fi
    fi
  fi
fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 \( -name *.conf -a \! -name *example \) -type f 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
if [ "$allconf" ]; then
  render_text "info" "All *.conf files in /etc (recursive 1 level)" "$allconf"

  if [ "$export" ]; then
    mkdir $format/conf-files/ 2> /dev/null
    for f in $allconf; do cp --parents $f $format/conf-files/; done 2> /dev/null
  fi
fi

# retrieves accessible history file paths (e.g. ~/.bash_history, ~/.wget-hsts, ~/.lesshst, ecc.)
# from users with valid home directories and shells
for entry in $(grep "^.*sh$" /etc/passwd 2> /dev/null); do
  user=`echo $entry | cut -d":" -f1`
  home=`echo $entry | cut -d":" -f6`
  usrhist=`ls ${_color_flag} -lah $home/.*_history $home/.*-hsts $home/.*hst 2> /dev/null`

  if [ "$usrhist" ]; then
    render_text "warning" "${user}'s history files" "$usrhist"

    # if requested we export history files
    if [ "$export" ]; then
      # create dir only if it does not exist
        mkdir -p $format/history_files/ 2> /dev/null
        for f in $usrhist; do cp --parents $f $format/history_files/; done 2> /dev/null
    fi
  fi
done

#all accessible .bash_history files in /home
checkbashhist=`find /home -name .bash_history -exec ls -lah {} 2> /dev/null \; -exec tail -n 30 {} 2> /dev/null \;  2> /dev/null`
if [ "$checkbashhist" ]; then
  render_text "info" "Location and contents (last 30 rows, if accessible) of .bash_history file(s)" "$checkbashhist"
fi

#hijack tmux session
tmux_installed=`which -- tmux 2> /dev/null`
if [ "$tmux_installed" ]; then
  # look for readable access to the tmux socket
  tmux_sessions=`find /var/tmp/tmux-*/default /tmp/tmux-*/default -type f -readable 2> /dev/null | xargs -r ls ${_color_flag} -lah 2> /dev/null`
  if [ "$tmux_sessions" ]; then
    render_text "danger" "Possible tmux session hijacking" "$tmux_sessions"
  fi
  
fi

#any bakup file that may be of interest
bakfiles="`find / \( -name *.bak -o -name *.tmp -o -name *.temp -o -name *.old -o -name *.001 -o -name *\~ \) -type f 2> /dev/null | \
           xargs -r ls ${_color_flag} -lah 2> /dev/null`"
if [ "$bakfiles" ]; then
  render_text "info" "Location and Permissions (if accessible) of backup file(s)" "$bakfiles"
fi

#is there any mail accessible
readmail=`ls ${_color_flag} -lah /var/mail 2> /dev/null`
if [ "$readmail" ]; then
  render_text "info" "Any interesting mail in /var/mail" "$readmail"
fi

#can we read roots mail
readmailroot=`head /var/mail/root 2> /dev/null`
if [ "$readmailroot" ]; then
  render_text "danger" "We can read /var/mail/root! (snippet below)" "$readmailroot"
  
  if [ "$export" ]; then
    mkdir $format/mail-from-root/ 2> /dev/null
    cp $readmailroot $format/mail-from-root/ 2> /dev/null
  fi
fi
}

docker_checks()
{

#specific checks - check to see if we're in a docker container
dockercontainer=`grep ${_color_flag} -i docker /proc/self/cgroup 2> /dev/null; find / -name "*dockerenv*" 2> /dev/null | \
                 xargs -r ls ${_color_flag} -lah 2> /dev/null`
if [ "$dockercontainer" ]; then
  render_text "warning" "It looks like we're in a Docker container" "$dockercontainer"
fi

#specific checks - check to see if we're a docker host
dockerhost=`docker --version 2> /dev/null; docker ps -a 2> /dev/null`
if [ "$dockerhost" ]; then
  render_text "info" "It looks like we're hosting Docker" "$dockerhost"
fi

#specific checks - are we a member of the docker group
dockergrp=`id | grep ${_color_flag} -i docker 2> /dev/null`
if [ "$dockergrp" ]; then
  render_text "warning" "We're a member of the (docker) group - could possibly misuse these rights!" "$dockergrp"
fi

#specific checks - are there any docker files present
dockerfiles=`find / -name Dockerfile* 2> /dev/null | xargs -r ls -lah 2> /dev/null`
if [ "$dockerfiles" ]; then
  render_text "warning" "Anything juicy in the Dockerfile" "$dockerfiles"
fi

#specific checks - are there any docker files present
dockeryml=`find / -name docker-compose.yml* 2> /dev/null | xargs -r ls -lah 2> /dev/null `
if [ "$dockeryml" ]; then
  render_text "warning" "Anything juicy in docker-compose.yml" "$dockeryml"
fi
}

lxc_container_checks()
{

#specific checks - are we in an lxd/lxc container
lxccontainer=`grep ${_color_flag} -qa container=lxc /proc/1/environ 2> /dev/null`
if [ "$lxccontainer" ]; then
  render_text "info" "It looks like we're in a lxc container" "$lxccontainer"
fi

#specific checks - are we a member of the lxd group
lxdgroup=`id | grep ${_color_flag} -i "(lxd)" 2> /dev/null`
if [ "$lxdgroup" ]; then
  render_text "warning" "We're a member of the (lxd) group - could possibly misuse these rights!" "$lxdgroup"
fi
}

footer()
{
echo -e "${_yellow}### SCAN COMPLETE ####################################${_reset}" 
}

call_each()
{
  banner
  debug_info
  system_info
  user_info
  environmental_info
  job_info
  networking_info
  services_info
  software_configs
  interesting_files
  docker_checks
  lxc_container_checks
  footer
}

while getopts "k:r:e:stCqh" option; do
  case "${option}" in
    k) keyword=${OPTARG};;
    r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
    e) export=${OPTARG};;
    s) sudopass=1;;
    t) thorough=1;;
    C) _reset=""; _red=""; _green=""; _yellow=""; _cyan=""; _purple=""; _gray=""; _color_flag="";;
    q) quiet=1;;
    h) usage; exit;;
    *) usage; exit;;
  esac
done

call_each | tee -a $report 2> /dev/null
#EndOfScript
