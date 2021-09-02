#!/bin/bash
#
#  LinEnum.sh - Local Linux Enumeration & Privilege Escalation Script:
#  a script to enumerate local information from a Linux host
#
#  Author: @rebootuser (up to version 0.982)
#          @filippolauria (from version 1.0)
#

###############
# variables
###############

# version number
version="1.0"

# colored output vars
_reset="\033[0m"
_red="\033[1;31m"
_green="\033[1;32m"
_yellow="\033[1;33m"
_purple="\033[1;35m"
_cyan="\033[1;36m"
_gray="\033[1;37m"
_color_flag="--color=always"

# we use sed to colorize some output
_sed_red="\o033[1;31m&\o033[0m"
_sed_yellow="\o033[1;33m&\o033[0m"

# set the number of columns
_cols="`tput cols 2> /dev/null || echo -n "120"`"
if [ "$_cols" -lt "120" ]; then _cols="120"; fi

# useful binaries (thanks to https://gtfobins.github.io/)
interesting_binaries='ansible-playbook\|apt-get\|apt\|ar\|aria2c\|arj\|arp\|ash\|at\|atobm\|awk\|base32\|base64\|basenc\|bash\|bpftrace\|bridge\|bundler\|busctl\|busybox\|byebug\|c89\|c99\|cancel\|capsh\|cat\|certbot\|check_by_ssh\|check_cups\|check_log\|check_memory\|check_raid\|check_ssl_cert\|check_statusfile\|chmod\|chown\|chroot\|cmp\|cobc\|column\|comm\|composer\|cowsay\|cowthink\|cp\|cpan\|cpio\|cpulimit\|crash\|crontab\|csh\|csplit\|csvtool\|cupsfilter\|curl\|cut\|dash\|date\|dd\|dialog\|diff\|dig\|dmesg\|dmidecode\|dmsetup\|dnf\|docker\|dpkg\|dvips\|easy_install\|eb\|ed\|emacs\|env\|eqn\|ex\|exiftool\|expand\|expect\|facter\|file\|find\|finger\|flock\|fmt\|fold\|ftp\|gawk\|gcc\|gdb\|gem\|genisoimage\|ghc\|ghci\|gimp\|git\|grep\|gtester\|gzip\|hd\|head\|hexdump\|highlight\|hping3\|iconv\|iftop\|install\|ionice\|ip\|irb\|jjs\|join\|journalctl\|jq\|jrunscript\|knife\|ksh\|ksshell\|latex\|ld.so\|ldconfig\|less\|ln\|loginctl\|logsave\|look\|ltrace\|lua\|lualatex\|luatex\|lwp-download\|lwp-request\|mail\|make\|man\|mawk\|more\|mount\|msgattrib\|msgcat\|msgconv\|msgfilter\|msgmerge\|msguniq\|mtr\|mv\|mysql\|nano\|nawk\|nc\|nice\|nl\|nmap\|node\|nohup\|npm\|nroff\|nsenter\|octave\|od\|openssl\|openvpn\|openvt\|paste\|pdb\|pdflatex\|pdftex\|perl\|pg\|php\|pic\|pico\|pip\|pkexec\|pkg\|pr\|pry\|psql\|puppet\|python\|rake\|readelf\|red\|redcarpet\|restic\|rev\|rlogin\|rlwrap\|rpm\|rpmquery\|rsync\|ruby\|run-mailcap\|run-parts\|rview\|rvim\|scp\|screen\|script\|sed\|service\|setarch\|sftp\|sg\|shuf\|slsh\|smbclient\|snap\|socat\|soelim\|sort\|split\|sqlite3\|ss\|ssh-keygen\|ssh-keyscan\|ssh\|start-stop-daemon\|stdbuf\|strace\|strings\|su\|sysctl\|systemctl\|systemd-resolve\|tac\|tail\|tar\|taskset\|tbl\|tclsh\|tcpdump\|tee\|telnet\|tex\|tftp\|tic\|time\|timedatectl\|timeout\|tmux\|top\|troff\|tshark\|ul\|unexpand\|uniq\|unshare\|update-alternatives\|uudecode\|uuencode\|valgrind\|vi\|view\|vigr\|vim\|vimdiff\|vipw\|virsh\|watch\|wc\|wget\|whois\|wish\|xargs\|xelatex\|xetex\|xmodmap\|xmore\|xxd\|xz\|yarn\|yelp\|yum\|zip\|zsh\|zsoelim\|zypper'

# interesting groups
interesting_groups="root\|sudo\|shadow\|adm\|wheel\|staff\|lxd\|lxc\|docker"

# interesting sudo keywords
interesting_sudo="env_keep+=LD_PRELOAD\|(\?ALL\s\?\(:\s\?ALL\)\?)\?\|NOPASSWD"

# current user id
myid=`(id || (groups | cut -d':' -f2)) 2> /dev/null`

###############
# utils
###############

# usage: print_title "color" "title"
print_title()
{
  color_var="_$1"
  if [ "${!color_var}" ]; then _color="${!color_var}"; else _color="${_yellow}"; fi
  
  if [ "$2" ]; then title="### $2 "; else title="#####"; fi
  title_len=`echo -n "$title" | wc -c`
  
  q=`expr \`expr $_cols / 2\` - $title_len`
  echo -n -e "${_color}$title"
  printf '#%.0s' `seq 1 $q`
  echo -e "${_reset}\n"
}

# usage: render_text "category" "keyword" "value"
render_text()
{
  case "$1" in
    "info") bullet="[${_cyan}-${_reset}]"; keyword_color="${_cyan}"; value_color="";;
    "danger") bullet="[${_red}!${_reset}]"; keyword_color="${_red}"; value_color="${_yellow}";;
    "warning") bullet="[${_yellow}!${_reset}]"; keyword_color="${_yellow}"; value_color="";;
    "success") bullet="[${_green}+${_reset}]"; keyword_color="${_green}"; value_color="";;
    "hint") bullet="[${_green}*${_reset}]"; keyword_color="${_green}"; value_color="";;
    *) bullet="[.]"; keyword_color=""; value_color="";;
  esac
  
  echo -e -n "${_gray}$bullet${_reset} ${keyword_color}$2${_reset}"
  if [ "$3" ]; then
    lines=`echo "$3" | wc -l`
    
    echo -e -n "${_gray}:${_reset}"
    if [ "$lines" -le "1" ]; then
      output="`echo $3 | sed 's,\n,,'`"
      total_chars=`echo "[.] $2: $output" | wc -c`
      if [ "$total_chars" -le "$_cols" ]; then
        first_char=" "
      else
        first_char="\n    "
      fi
    else
      first_char="\n"
    fi
    echo -e "$first_char${value_color}$3${_reset}\n"

  else echo -e "\n"; fi
}

print_ls_lah()
{
  if [ "$1" ]; then
    ((for f in $1; do [[ -e "$f" ]] || continue; ls ${_color_flag} -lah "$f"; done) | head -n50) 2> /dev/null
  fi
}

banner()
{
  print_title "red"

if [ -z "$quiet" ]; then
  echo -e "${_yellow}      _              ______                       
     | |    (o)     |  ____|                      
     | |     _ _ __ | |__   _ __  _   _ _ __ ___  
     | |    | | \`_ \\|  __| | \`_ \\| | | | '_ \` _ \\ 
     | |____| | | | | |____| | | | |_| | | | | | |
     |______|_|_| |_|______|_| |_|\\__,_|_| |_| |_| v${_yellow}$version
${_reset}
  Local Linux Enumeration & Privilege Escalation Script
"
print_title "red"
fi
}

usage ()
{ 
banner
echo -e "OPTIONS:
-q	Quiet mode
-C	Disable colored output
-s 	Supply user password for sudo checks (INSECURE)
-t	Include thorough (lengthy) tests
-k	Enter keyword
-r	Enter report name
-e	Enter export location
-h	Displays this help text

${_yellow}Running with no options = limited scans/no output file${_reset}

EXAMPLE:
    ./LinEnum.sh -t -k password -r report -e /tmp/
"
print_title "red"
}

###############
# checks
###############

debug_info()
{
print_title "yellow" "INFO"

if [ "$keyword" ]; then 
  render_text "info" "Searching for the following keyword in conf, php, ini and log files" "$keyword"
fi

if [ "$report" ]; then render_text "info" "Report name" "$report"; fi

if [ "$export" ]; then render_text "info" "Export location" "$export"; fi

render_text "info" "Thorough tests" "`if [ "$thorough" ]; then echo -n "Enabled"; else echo -n "Disabled"; fi`"
echo

sleep 2

# prepare to export findings
if [ "$export" ]; then
  mkdir "$export" 2> /dev/null
  format=$export/LinEnum-export-`date +"%d-%m-%y"`
  mkdir "$format" 2> /dev/null
fi

# prepare password
if [ "$sudopass" ]; then 
  render_text "warning" "Please enter password - INSECURE - really only for CTF use!"
  read -s -r userpassword
  echo 
fi

}

system_info()
{
print_title "yellow" "SYSTEM"

#basic kernel info
unameinfo=`uname -a 2> /dev/null`
if [ "$unameinfo" ]; then
  render_text "info" "Kernel information" "$unameinfo"  
fi

procver=`cat /proc/version 2> /dev/null`
if [ "$procver" ]; then
  render_text "info" "Kernel information (continued)" "$procver"
fi

render_text "hint" "Use 'searchsploit `uname -s` Kernel `uname -r | cut -d'.' -f1-2`' to look for kernel exploits"

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
print_title "yellow" "USER/GROUP" 

#current user details
render_text "info" "Current user/group info" \
                   "`(echo "$myid" | sed "s,\((\|\s\)\($interesting_groups\)\()\|\s\),${_sed_yellow},g") 2> /dev/null`"


#last logged on user information
lastlogedonusrs=`(lastlog | grep -v "Never") 2> /dev/null`
if [ "$lastlogedonusrs" ]; then
  render_text "info" "Users that have previously logged onto the system" "$lastlogedonusrs"
fi

#who else is logged on
loggedonusrs=`w 2> /dev/null`
if [ "`echo "$loggedonusrs" | wc -l`" -gt "1" ]; then
  render_text "info" "Who else is logged on" "$loggedonusrs"
fi

# save all users in the users variable
users=`(grep -v '^#\|^$' /etc/passwd | cut -d":" -f1) 2> /dev/null`

#lists all id's and respective group(s)
grpinfo=""
for u in $users; do
  idoutput=`((id $u || (groups $u | cut -d':' -f2)) | sed "s,\((\|\s\)\($interesting_groups\)\()\|\s\),${_sed_yellow},g") 2> /dev/null`
  entry="${_cyan}$u${_reset} : $idoutput"
  
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
readpasswd=`(cat /etc/passwd | sed "s/.*sh$/${_sed_red}/") 2> /dev/null`
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
sudobin=`command -v sudo 2> /dev/null`
if [ "$sudobin" ]; then

  # we get /etc/sudoers content,
  # strip out comments and empty lines
  # and highlight interesting keywords
  sudoers=`grep -v '^#\|^$' /etc/sudoers 2> /dev/null`
  if [ "$sudoers" ]; then
    sudoers=`(echo "$sudoers" | sed "s,$interesting_sudo,${_sed_red},g" | sed "s,$interesting_binaries,${_sed_yellow},g") 2> /dev/null`
    render_text "warning" "We can read /etc/sudoers" "$sudoers"
    
    if [ "$export" ]; then
      mkdir $format/etc-export/ 2> /dev/null
      cp /etc/sudoers $format/etc-export/sudoers 2> /dev/null
    fi
  fi
  
  # check if we can sudo without password
  sudoperms=`(echo '' | sudo -S -l -k) 2> /dev/null`
  if [ "$sudoperms" ]; then
    sudoperms=`(echo "$sudoperms" | sed "s,$interesting_sudo,${_sed_red},g" | sed "s,$interesting_binaries,${_sed_yellow},g") 2> /dev/null`
    render_text "danger" "We can 'sudo -l' without supplying a password" "$sudoperms"
  else
    if [ "$sudopass" ]; then
      # check if we can sudo with password
      sudoauth=`(echo $userpassword | sudo -S -l -k) 2> /dev/null`
      
      if [ "$sudoauth" ]; then
        sudoauth=`(echo "$sudoauth" | sed "s,$interesting_sudo,${_sed_red},g" | sed "s,$interesting_binaries,${_sed_yellow},g") 2> /dev/null`
        render_text "danger" "We can sudo when supplying a password" "$sudoauth"
      fi
    fi
  fi

  # check for writable/readable files in /etc/sudoers.d
  sudoersd=`find /etc/sudoers.d \! -name README -type f -exec ls -lah {} \; 2> /dev/null`
  if [ "$sudoersd" ]; then
    render_text "danger" "Check if we can read/write files in /etc/sudoers.d" "$sudoersd"
    
    if [ "$export" ]; then
      mkdir -p $format/etc-export/sudoers.d/ 2> /dev/null
      cp /etc/sudoers.d/* $format/etc-export/sudoers.d/ 2> /dev/null
    fi
  fi

  # who has sudoed in the past
  sudoerhomelist="`(find /home -name .sudo_as_admin_successful -type f -exec dirname {} \; | sort -u) 2> /dev/null`"
  if [ "$sudoerhomelist" ]; then
    sudoerslist=""
    for h in $sudoerhomelist; do
      entry=`(ls -dl "$h" 2> /dev/null | awk 'NR==1 {print $3}') 2> /dev/null`
      if [ "$sudoerslist" ]; then sudoerslist="$sudoerslist"$'\n'"$entry"; else sudoerslist="$entry"; fi
    done
    
    if [ "$sudoerslist" ]; then
        render_text "info" "Users that have recently used sudo" "$sudoerslist"
    fi
  fi
fi

#checks to see if roots home directory is accessible
rthmdir=`ls ${_color_flag} -lah /root/ 2> /dev/null`
if [ "$rthmdir" ]; then
  render_text "danger" "We can read root's home directory" "$rthmdir"
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls ${_color_flag} -lah /home/ 2> /dev/null`
if [ "$homedirperms" ]; then
  render_text "info" "Check if permissions on /home directories are lax" "$homedirperms"
fi

# # we proceed with ssh checks, only if we can read /etc/ssh/sshd_config
if [ -r "/etc/ssh/sshd_config" ]; then
  #~ https://www.cyberciti.biz/tips/linux-unix-bsd-openssh-server-best-practices.html

  #is root permitted to login via ssh
  sshrootlogin=`(grep '^\s*PermitRootLogin\s\+' /etc/ssh/sshd_config) 2> /dev/null`
  if [ -z "$sshrootlogin" ]; then sshrootlogin="no"; fi
  render_text "info" "Check if root is allowed to login via SSH" "$sshrootlogin"
fi

#thorough checks
if [ "$thorough" = "1" ]; then
  current_user=`whoami 2> /dev/null`
  current_user_homedir=`(cat /etc/passwd | grep "^$current_user" | cut -d':' -f6) 2> /dev/null`
  
  #looks for files we can write to that don't belong to us
  grfilesall=`find / -writable \! -user $current_user -type f \! \( -path "/proc/*" -o -path "/sys/*" \) 2> /dev/null`
  if [ "$grfilesall" ]; then
    render_text "info" "Files not owned by user but writable by group" "`print_ls_lah "$grfilesall"`"
  fi

  #looks for files that belong to us
  ourfilesall=`find / -user $current_user -type f \! \( -path "/proc/*" -o -path "/sys/*" \) 2> /dev/null`
  if [ "$ourfilesall" ]; then
    render_text "info" "Files owned by our user" "`print_ls_lah "$ourfilesall"`"
  fi

  #looks for hidden files
  hiddenfiles=`find / -name .* -type f \! \( -path "/proc/*" -o -path "/sys/*" \) 2> /dev/null`
  if [ "$hiddenfiles" ]; then
    render_text "warning" "Hidden files" "`print_ls_lah "$hiddenfiles"`"
  fi
  
  # looks for world-reabable files within /home
  wrfilesinhome=`find /home/ -perm -4 -type f 2> /dev/null`
  if [ "$wrfilesinhome" ]; then
    render_text "warning" "World-readable files within /home" "`print_ls_lah "$wrfilesinhome"`"

    if [ "$export" ]; then
      mkdir $format/wr-files/ 2> /dev/null
      for f in $wrfilesinhome; do cp --parents "$f" $format/wr-files/; done 2> /dev/null
    fi
  fi

  # lists current user's home directory contents
  homedircontents=`ls ${_color_flag} -Rlah "$current_user_homedir" 2> /dev/null`
  if [ "$homedircontents" ] ; then
    render_text "info" "Home directory contents" "$homedircontents"
  fi
  
  # checks for if various ssh files (or their backups) are accessible
  sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts*" -o -name "authorized_hosts*" -o -name "authorized_keys*" \) -type f 2> /dev/null`
  if [ "$sshfiles" ]; then
    render_text "warning" "SSH keys/host information found in the following locations" "`print_ls_lah "$sshfiles"`"

    if [ "$export" ]; then
      mkdir $format/ssh-files/ 2> /dev/null
      for f in $sshfiles; do cp --parents "$f" $format/ssh-files/; done 2> /dev/null
    fi
  fi
fi
}

environmental_info()
{
print_title "yellow" "ENVIRONMENT"

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

if [[ -f "/etc/login.defs" ]]; then
  #umask value as in /etc/login.defs
  umaskdef=`(grep -i "^UMASK" /etc/login.defs | sed -E 's/\s+/ /') 2> /dev/null`
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
fi

#In-memory passwords
inmemorypassword=`strings /dev/mem -n10 2> /dev/null | grep ${_color_flag} -i PASS`
if [ "$inmemorypassword" ]; then
  render_text "danger" "In-memory passwords" "$inmemorypassword"
fi
}

job_info()
{
print_title "yellow" "JOBS/TASKS"

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
for u in $users; do
  cronother=`crontab -l -u $u 2> /dev/null`
  if [ "$cronother" ]; then
    render_text "warning" "Jobs held by $u" "$cronother"
  fi
done

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
print_title "yellow" "NETWORKING" 

#nic information
nicinfo=`(ifconfig -a || /sbin/ifconfig -a) 2> /dev/null`
if [ "$nicinfo" ]; then
  render_text "info" "Network and IP info" "$nicinfo"
else
  #nic information (using ip)
  nicinfoip=`(ip addr || /sbin/ip addr) 2> /dev/null`
  if [ "$nicinfoip" ]; then
    render_text "info" "Network and IP info" "$nicinfoip"
  fi
fi

#arp information
arpinfo=`(arp -a || /usr/sbin/arp -a) 2> /dev/null`
if [ -z "$arpinfo" ]; then
  #arp information (using ip)
  arpinfo=`(ip neigh || /sbin/ip neigh) 2> /dev/null`
fi

if [ "$arpinfo" ]; then
  render_text "info" "ARP history" "$arpinfo"
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
defroute=`(route -n || /usr/sbin/route -n) 2> /dev/null | grep '^\(0.\?\)\{4\}'`
if [ -z "$defroute" ]; then
  #default route configuration (using ip)
  defroute=`(ip r || /sbin/ip r) 2> /dev/null | grep default`
fi
  
if [ "$defroute" ]; then
  render_text "info" "Default route" "$defroute"
fi

#listening TCP
tcpserv=`(netstat -lntp | sed "s,127.0.0.1:[0-9]\+,${_sed_yellow},") 2> /dev/null`
if [ -z "$tcpserv" ]; then
  #listening TCP (using ss)
  tcpserv=`(ss -lntp | sed "s,127.0.0.1:[0-9]\+,${_sed_yellow},") 2> /dev/null`
fi

if [ "$tcpserv" ]; then
  render_text "info" "Listening TCP" "$tcpserv"
fi

#listening UDP
udpserv=`netstat -lnup 2> /dev/null`
if [ "$udpserv" ]; then
  #listening UDP (using ss)
  udpservsip=`ss -lnup 2> /dev/null`
fi

if [ "$udpserv" ]; then
  render_text "info" "Listening UDP" "$udpserv"
fi
}

services_info()
{
print_title "yellow" "SERVICES" 

#running processes
psaux=`ps aux 2> /dev/null`
if [ "$psaux" ]; then
  render_text "info" "Running processes" "$psaux"
fi

#lookup process binary path and permissisons
psoutput=`(ps -eo command | grep -v "^\(\[\|COMMAND\|(\)" | awk '{print $1}' | awk '!x[$0]++') 2> /dev/null`
if [ "$psoutput" ]; then
  proclist=""
  for proc in $psoutput; do
    procpath="`command -v -- $proc 2> /dev/null`"
    if [ "$proclist" ]; then proclist="$proclist"$'\n'"$procpath"; else proclist="$procpath"; fi
  done
  
  if [ "$proclist" ]; then
    render_text "info" "Process binaries and associated permissions (from the above list)" "`ls ${_color_flag} -lah $proclist 2> /dev/null`"
  
    if [ "$export" ]; then
      mkdir $format/ps-export/ 2> /dev/null
      for binary in $proclist; do cp --parents $binary $format/ps-export/; done 2> /dev/null
    fi
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
inetdbinperms=`awk '{print $7}' /etc/inetd.conf 2> /dev/null`
if [ "$inetdbinperms" ]; then
  render_text "info" "The related inetd binary permissions" "`print_ls_lah "$inetdbinperms"`"
fi

#check /etc/xinetd.conf file content
xinetdread=`grep -v '^#\|^$' /etc/xinetd.conf 2> /dev/null`
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
  render_text "info" "/etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below" \
                     "`ls ${_color_flag} -lah /etc/xinetd.d 2> /dev/null`"
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`awk '{print $7}' /etc/xinetd.conf 2> /dev/null`
if [ "$xinetdbinperms" ]; then
  render_text "info" "The related xinetd binary permissions" "`print_ls_lah "$xinetdbinperms"`"
fi

initdread=`ls ${_color_flag} -lah /etc/init.d 2> /dev/null`
if [ "$initdread" ]; then
  render_text "info" "/etc/init.d/ binary permissions" "$initdread"
fi

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2> /dev/null`
if [ "$initdperms" ]; then
  render_text "info" "/etc/init.d/ files not belonging to root" "`print_ls_lah "$initdperms"`"
fi

rcdread=`ls ${_color_flag} -la /etc/rc.d/init.d 2> /dev/null`
if [ "$rcdread" ]; then
  render_text "info" "/etc/rc.d/init.d binary permissions" "$rcdread"
fi

#init.d files NOT belonging to root!
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2> /dev/null`
if [ "$rcdperms" ]; then
  render_text "danger" "/etc/rc.d/init.d files not belonging to root" "`print_ls_lah "$rcdperms"`"
fi

usrrcdread=`ls ${_color_flag} -lah /usr/local/etc/rc.d 2> /dev/null`
if [ "$usrrcdread" ]; then
  render_text "info" "/usr/local/etc/rc.d binary permissions" "$usrrcdread"
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2> /dev/null`
if [ "$usrrcdperms" ]; then
  render_text "danger" "/usr/local/etc/rc.d files not belonging to root" "`print_ls_lah "$xinetdbinperms"`"
fi

initread=`ls ${_color_flag} -la /etc/init/ 2> /dev/null`
if [ "$initread" ]; then
  render_text "info" "/etc/init/ config file permissions" "$initread"
fi

# upstart scripts not belonging to root
initperms=`find /etc/init \! -uid 0 -type f 2> /dev/null`
if [ "$initperms" ]; then
   render_text "danger" "/etc/init/ config files not belonging to root" "`print_ls_lah "$initdperms"`"
fi

if [ "$thorough" = "1" ]; then
  systemdread="`find /lib/systemd/ /etc/systemd/ -type f 2> /dev/null`";
  systemdperms="`find /lib/systemd/ /etc/systemd/ \( \! -uid 0 -o -writable \) -type f 2> /dev/null`"
else
  systemdread="`find /lib/systemd/ /etc/systemd/ -name *.service -type f 2> /dev/null`"
  systemdperms="`find /lib/systemd/ /etc/systemd/ \( \! -uid 0 -o -writable \) -name *.service -type f 2> /dev/null`"
fi

# systemd files
if [ "$systemdread" ]; then
  render_text "info" "systemd config file permissions" "`print_ls_lah "$systemdread"`"
fi

# systemd files not belonging to root or writable
if [ "$systemdperms" ]; then
   render_text "danger" "systemd config files not belonging to root or writable" "`print_ls_lah "$systemdperms"`"
fi
}

software_configs()
{
print_title "yellow" "SOFTWARE"

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`(sudo -V | head -n1 | cut -d' ' -f3) 2> /dev/null`
if [ "$sudover" ]; then
  render_text "info" "Sudo version" "$sudover"
fi

#exim4 details - if installed
exim4ver=`(exim4 --version | head -n1 | cut -d' ' -f3) 2> /dev/null`
if [ "$exim4ver" ]; then
  render_text "info" "Exim4 version" "$exim4ver"
fi

#mysql details - if installed
mysqlver=`mysql --version 2> /dev/null`
if [ "$mysqlver" ]; then
  render_text "info" "MYSQL version" "$mysqlver"
  
  #checks to see if we can get very low MYSQL hanging fruits
  mysql_usernames="root `whoami`"
  mysql_passwords="root toor `whoami`"
  for u in $mysql_usernames; do
    for p in $mysql_passwords; do
      mysqlcon=`mysqladmin -u$u -p$p version 2> /dev/null`

      if [ "$mysqlcon" ]; then
        render_text "danger" "We can connect to MYSQL service as $u with password $p" "$mysqlcon"
      fi
      
    done
    
    # test connection without password 
    mysqlcon=`mysqladmin -u$u version 2> /dev/null`
    if [ "$mysqlcon" ]; then
      render_text "danger" "We can connect to the MYSQL service as $u with no password" "$mysqlcon"
    fi
  done
fi

#postgres details - if installed
postgver=`psql -V 2> /dev/null`
if [ "$postgver" ]; then
  render_text "info" "Postgres version" "$postgver"

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
fi

#apache details - if installed
apachever=`((apache2 -v || httpd -v) | head -n1 | awk -F': ' '{ print $2 }') 2> /dev/null`
if [ "$apachever" ]; then
  render_text "info" "Apache version" "$apachever"

  #what user:group is running apache daemon?
  if [[ -f "/etc/apache2/envvars" ]]; then
    apacheusr=`(grep -i 'user' /etc/apache2/envvars | cut -d'=' -f2) 2> /dev/null`
    apachegrp=`(grep -i 'group' /etc/apache2/envvars | cut -d'=' -f2) 2> /dev/null`
    
    if [ "$apacheusr" ] && [ "$apachegrp" ]; then
      render_text "info" "Apache is running as (user:group)" "$apacheusr:$apachegrp"

      if [ "$export" ]; then
        mkdir --parents $format/etc-export/apache2/ 2> /dev/null
        cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2> /dev/null
      fi
    fi
  fi

  #installed apache modules
  apachemodules=`(apache2ctl -M || httpd -M) 2> /dev/null`
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
fi
}

interesting_files()
{
print_title "yellow" "INTERESTING FILES"

#checks to see if various files are installed
bin_of_interest="nc netcat socat wget nmap ncat gcc curl ftp"
bin_fullpath=`command -v -- $bin_of_interest 2> /dev/null`
if [ "$bin_fullpath" ]; then
  render_text "info" "Useful utilities" "`print_ls_lah "$bin_fullpath"`"
fi

#limited search for installed compilers
compiler=`((dpkg --list | grep '\s\+compiler') || (yum list installed 'gcc*' | grep gcc)) 2> /dev/null`
if [ "$compiler" ]; then
  render_text "info" "Installed compilers" "$compiler"
fi

#manual check - lists out sensitive files, can we read/modify etc.
sensitive_files="/etc/passwd /etc/group /etc/profile /etc/shadow /etc/master.passwd /etc/security/opasswd"
render_text "warning" "Check if we can read/write sensitive files" "`print_ls_lah "$sensitive_files"`"

# regular files that have changed in the last 10 minutes
changedfiles=`find / -mmin 10 \! -path "/proc/*" -type f 2> /dev/null`
if [ "$changedfiles" ]; then
  render_text "warning" "Regular files that have changed in the last 10 minutes" "`print_ls_lah "$changedfiles"`"
fi

#search for suid files
allsuid=`find / -perm -4000 -type f 2> /dev/null`
if [ "$allsuid" ]; then
  allsuiddetails="`print_ls_lah "$allsuid"`"
  if [ "$allsuiddetails" ]; then
    render_text "info" "SUID files" "$allsuiddetails"

    #list of 'interesting' suid files - feel free to make additions
    interestingsuid=`(echo "$allsuiddetails" | grep -w $interesting_binaries) 2> /dev/null`
    if [ "$interestingsuid" ]; then
      render_text "warning" "Possibly interesting SUID files" "$interestingsuid"
    fi
  fi

  #lists world-writable suid files
  wwsuid=`find $allsuid \! -uid 0 -perm -4002 -type f 2> /dev/null`
  if [ "$wwsuid" ]; then
    render_text "warning" "World-writable SUID files" "`print_ls_lah "$wwsuid"`"
  fi

  #lists world-writable suid files owned by root
  wwrootsuid=`find $allsuid -uid 0 -perm -4002 -type f 2> /dev/null`
  if [ "$wwrootsuid" ]; then
    render_text "warning" "World-writable SUID files owned by root" "`print_ls_lah "$wwrootsuid"`"
  fi

  if [ "$export" ]; then
    mkdir $format/suid-files/ 2> /dev/null
    for f in $allsuid; do cp $f $format/suid-files/; done 2> /dev/null
  fi
fi

#search for sgid files
allsgid=`find / -perm -2000 -type f 2> /dev/null`
if [ "$allsgid" ]; then
  allsgiddetails="`print_ls_lah "$allsgid"`"
  if [ "$allsgiddetails" ]; then
    render_text "info" "SGID files" "$allsgiddetails"

    #list of 'interesting' sgid files
    interestingsgid=`echo "$allsgiddetails" | grep -w $interesting_binaries 2> /dev/null`
    if [ "$interestingsgid" ]; then
      render_text "warning" "Possibly interesting SGID files" "$interestingsgid"
    fi
  fi
  
  #lists world-writable sgid files
  wwsgid=`find $allsgid \! -uid 0 -perm -2002 -type f 2> /dev/null`
  if [ "$wwsgid" ]; then
    render_text "warning" "World-writable SGID files" "`print_ls_lah "$wwsgid"`"
  fi

  #lists world-writable sgid files owned by root
  wwrootsgid=`find $allsgid -uid 0 -perm -2002 -type f 2> /dev/null`
  if [ "$wwrootsgid" ]; then
    render_text "warning" "World-writable SGID files owned by root" "`print_ls_lah "$wwrootsgid"`"
  fi
  
  if [ "$export" ]; then
    mkdir $format/sgid-files/ 2> /dev/null
    for f in $allsgid; do cp $f $format/sgid-files/; done 2> /dev/null
  fi
fi

#list all files with POSIX capabilities set along with there capabilities
fileswithcaps=`(getcap -r / || /sbin/getcap -r /) 2> /dev/null`
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
  matchedcaps=`(echo -e "$userswithcaps" | grep \`whoami\` | awk '{print $1}') 2> /dev/null`
  if [ "$matchedcaps" ]; then
    render_text "info" "Capabilities associated with the current user" "$matchedcaps"

    #matches the files with capapbilities with capabilities associated with the current user
    matchedfiles=`(echo -e "$matchedcaps" | while read -r cap; do echo -e "$fileswithcaps" | grep "$cap"; done) 2> /dev/null`
    if [ "$matchedfiles" ]; then
      render_text "warning" "Files with the same capabilities associated with the current user (You may want to try abusing those capabilties)" "$matchedfiles"
      
      #lists the permissions of the files having the same capabilies associated with the current user
      matchedfilesperms=`(echo -e "$matchedfiles" | awk '{print $1}') 2> /dev/null`
      render_text "info" "Permissions of files with the same capabilities associated with the current user" "`print_ls_lah "$matchedfilesperms"`"
      
      if [ "$matchedfilesperms" ]; then
        #checks if any of the files with same capabilities associated with the current user is writable
        writablematchedfiles=`(echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do find $f -writable; done) 2> /dev/null`
        if [ "$writablematchedfiles" ]; then
          render_text "info" "User/Group writable files with the same capabilities associated with the current user" "`print_ls_lah "$writablematchedfiles"`"
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

#looking for credentials in /etc/fstab and /etc/mtab
tabfiles="/etc/fstab /etc/mtab"
for f in $tabfiles; do
  [[ -e "$f" ]] || continue
  
  tabcreds=`grep "\(credentials\|login\|user\(name\)\?\|pass\(word\)\?\|pwd\?\)[=]" $f 2> /dev/null`
  if [ "$tabcreds" ]; then
    render_text "warning" "Look for possible credentials in $f" "`cat $f 2> /dev/null`"
  else
    if [ "$thorough" = "1" ]; then
      render_text "info" "NFS displaying partitions and filesystems - you need to look for exotic filesystems" "$f"
    fi
  fi
  
  if [ "$export" ]; then
    mkdir $format/etc-exports/ 2> /dev/null
    cp "$f" $format/etc-exports/ 2> /dev/null
  fi
  
done

#can we read some log?
readablelogs=`find /etc/log /var/log -type f -name *log* -readable 2> /dev/null`
if [ "$readablelogs" ]; then
  render_text "warning" "We can read these log files content" "`print_ls_lah "$readablelogs"`"
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
allconf=`find /etc/ -maxdepth 1 \( -name *.conf -a \! -name *example \) -type f -exec ls -lah {} \; 2> /dev/null`
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
checkbashhist=`find /home -name .bash_history -exec ls -lah {} \; -exec tail -n 30 {} \;  2> /dev/null`
if [ "$checkbashhist" ]; then
  render_text "info" "Location and contents (last 30 rows, if accessible) of .bash_history file(s)" "$checkbashhist"
fi

#hijack tmux session
tmux_installed=`command -v tmux 2> /dev/null`
if [ "$tmux_installed" ]; then
  # look for readable access to the tmux socket
  tmux_sessions=`find /var/tmp/tmux-*/default /tmp/tmux-*/default -type f -readable -exec ls -lah {} \; 2> /dev/null`
  if [ "$tmux_sessions" ]; then
    render_text "danger" "Possible tmux session hijacking" "$tmux_sessions"
  fi
  
fi

#any bakup file that may be of interest
bakfiles="`find / \( -name *.bak -o -name *.tmp -o -name *.temp -o -name *.old -o -name *.001 -o -name *\~ \) -type f -exec ls -lah {} \; 2> /dev/null`"
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
print_title "yellow" "DOCKER CHECKS"
#specific checks - check to see if we're in a docker container
dockerproc=`(grep -i docker /proc/self/cgroup; \
             find / -name "*dockerenv*" \! \( -path "/proc/*" -o -path "/sys/*" \) -exec ls -lah {} \;) 2> /dev/null`
if [ "$dockercontainer" ]; then
  render_text "warning" "It looks like we're in a Docker container" "$dockercontainer"
fi

#specific checks - check to see if we're a docker host
dockerhost=`(docker --version; docker ps -a) 2> /dev/null`
if [ "$dockerhost" ]; then
  render_text "info" "It looks like we're hosting Docker" "$dockerhost"
fi

#specific checks - are we a member of the docker group
if `(echo "$myid" | grep -q "\((\|\s\)\(docker\)\()\|\s\)") 2> /dev/null`; then
  render_text "warning" "We're a member of the (docker) group - could possibly misuse these rights!" \
                        "`(echo "$myid" | sed "s,\((\|\s\)\(docker\)\()\|\s\),${_sed_yellow},g") 2> /dev/null`"
fi

#specific checks - are there any docker files present
dockerfiles=`find / \( -name Dockerfile* -o -name docker-compose.yml* \) -type f -exec ls -lah {} \; 2> /dev/null`
if [ "$dockerfiles" ]; then
  render_text "warning" "Checks for Dokerfile(s) and docker-compose.yml(s)" "$dockerfiles"
fi

# check if we can access some docker socket
dockersock=`find / \! \( -path "/proc/*" -o -path "/sys/*" \) -type s -name "docker.sock" -o -name "docker.socket" -exec \ ls -lah {} \; 2> /dev/null`
if [ "$dockersock" ]; then
  render_text "info" "Check if we can read from/write to docker socket(s)" "$dockersock"
fi
}

lxc_container_checks()
{
print_title "yellow" "LXC/LXD CHECKS"
#specific checks - are we in an lxd/lxc container
lxccontainer=`grep ${_color_flag} -qa container=lxc /proc/1/environ 2> /dev/null`
if [ "$lxccontainer" ]; then
  render_text "info" "It looks like we're in a lxc container" "$lxccontainer"
fi

#specific checks - are we a member of the lxd group
if `(echo "$myid" | grep -q '\((\|\s\)\(lxd\|lxc\)\()\|\s\)') 2> /dev/null`; then
  render_text "warning" "We're a member of the (lxc/lxd) group - could possibly misuse these rights!" \
                        "`(echo "$myid" | sed "s,\((\|\s\)\(lxd\|lxc\)\()\|\s\),${_sed_yellow},g") 2> /dev/null`"
fi
}

call_each()
{
  banner
  debug_info
  
  # head
  start_epoch=`date +%s`
  print_title "green" "Scan started at `date +%R`"
  
  #PATH manipulation, in debian some directory (e.g. /sbin or /usr/sbin) is not added to the path
  # this manipulation adds some known dir to the path, if it exists on the system
  OLD_PATH=$PATH
  known_good_path_dirs="/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin /usr/games /usr/local/games /snap/bin"
  path_manipulated=0
  for d in $known_good_path_dirs; do
  
    if [[ -d "$d" ]] && [[ ! "$PATH" =~ "$d" ]]; then
      PATH="$PATH:$d"
      path_manipulated=1
    fi
  done

  if [ "$path_manipulated" = "1" ]; then
    render_text "warning" "Path changed to: $PATH"
  fi
  
  # call checks
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
  
  # foot
  end_epoch=`date +%s`
  seconds=`expr $end_epoch - $start_epoch`
  print_title "green" "Scan ended at `date +%R` (completed in $seconds secs)"
}

while getopts "qCstk:r:e:h" option; do
  case "${option}" in
    q) quiet=1;;
    C) _reset=""; _red=""; _green=""; _yellow=""; _cyan=""; _purple=""; _gray=""; _color_flag=""
       _sed_red="\o033[4m&\o033[0m"; _sed_yellow="\o033[4m&\o033[0m"
    ;;
    s) sudopass=1;;
    t) thorough=1;;
    
    k) keyword=${OPTARG};;
    r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
    e) export=${OPTARG};;
    
    h) usage; exit;;
    *) usage; exit;;
  esac
done

call_each | tee -a $report 2> /dev/null
#EndOfScript
