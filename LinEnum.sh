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
_sed_green="\o033[1;32m&\o033[0m"
_sed_yellow="\o033[1;33m&\o033[0m"
_sed_cyan="\o033[1;36m&\o033[0m"

# set the number of columns
_cols="`tput cols 2> /dev/null || echo -n "120"`"
if [ "$_cols" -lt "120" ]; then _cols="120"; fi

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
  
  half_cols=`expr "$_cols" / 2`
  q=`expr "$half_cols" - "$title_len"`
  echo -n -e "${_color}$title"
  printf '#%.0s' `seq 1 "$q"`
  echo -e "${_reset}\n"
}

# usage: render_text "category" "keyword" "value"
render_text()
{
  case "$1" in
    "info") bullet="[${_cyan}-${_reset}]"; keyword_color="${_cyan}"; value_color="";;
    "danger") bullet="[${_red}!${_reset}]"; keyword_color="${_red}"; value_color="";;
    "warning") bullet="[${_yellow}!${_reset}]"; keyword_color="${_yellow}"; value_color="";;
    "success") bullet="[${_green}+${_reset}]"; keyword_color="${_green}"; value_color="";;
    "hint") bullet="[${_purple}*${_reset}]"; keyword_color="${_purple}"; value_color="";;
    *) bullet="[.]"; keyword_color=""; value_color="";;
  esac
  
  echo -e -n "${_gray}$bullet${_reset} ${keyword_color}$2${_reset}"
  if [ "$3" ]; then
    lines=`echo "$3" | wc -l`
    
    echo -e -n "${_gray}:${_reset}"
    if [ "$lines" -le "1" ]; then
      output="`echo "$3" | sed 's,\n,,'`"
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

print_ls_lh()
{
  if [ "$1" ]; then
    
    if [ "`(echo "$1" | wc -l) 2> /dev/null`" -le "$max_listable_files" ]; then
      args="$1"
    else
      args="`(echo "$1" | head -n${max_listable_files}) 2> /dev/null`"
      echo "${_yellow}... (only $max_listable_files entries shown)${_reset}"
    fi
    OLD_IFS=$IFS; IFS=$'\n'
    find $args -exec ls -lh ${_color_flag} {} + 2> /dev/null
    IFS=$OLD_IFS
  fi
}

banner()
{
if [ "$quiet" ]; then
  echo
else
  print_title "red"
  
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
echo -e "USAGE:
    ./LinEnum.sh -qCst -k <keyword> -r <report name> -e <export location> -h

OPTIONS:
  -q  Quiet mode
  -C  Disable colored output
  -s  Supply user password for sudo checks (INSECURE)
  -t  Include thorough (lengthy) tests
  -k  Enter keyword
  -r  Enter report name
  -e  Enter export location
  -h  Displays this help text

${_yellow}Running with no options = limited scans/no output file${_reset}

EXAMPLE:
    ./LinEnum.sh -t -k password -r report -e /tmp/
"
print_title "red"
}

common()
{
  render_text "hint" "Please wait while the scan is starting..."
  
  # maximum number of files listable
  max_listable_files=70
  
  # useful binaries (thanks to https://gtfobins.github.io/)
  # update this list with:
  # wget -q -O- https://gtfobins.github.io/ | grep -o 'bin-name">.*</a>' | sed 's,^.*">\(.*\)</a>,\1,g' | sed ':a;N;$!ba;s,\n,\\|,g'
  interesting_binaries='ansible-playbook\|apt-get\|apt\|ar\|aria2c\|arj\|arp\|as\|ash\|at\|atobm\|awk\|base32\|base64\|basenc\|bash\|bpftrace\|bridge\|bundler\|busctl\|busybox\|byebug\|bzip2\|c89\|c99\|cancel\|capsh\|cat\|certbot\|check_by_ssh\|check_cups\|check_log\|check_memory\|check_raid\|check_ssl_cert\|check_statusfile\|chmod\|chown\|chroot\|cmp\|cobc\|column\|comm\|composer\|cowsay\|cowthink\|cp\|cpan\|cpio\|cpulimit\|crash\|crontab\|csh\|csplit\|csvtool\|cupsfilter\|curl\|cut\|dash\|date\|dd\|dialog\|diff\|dig\|dmesg\|dmidecode\|dmsetup\|dnf\|docker\|dosbox\|dpkg\|dvips\|easy_install\|eb\|ed\|emacs\|env\|eqn\|ex\|exiftool\|expand\|expect\|facter\|file\|find\|finger\|flock\|fmt\|fold\|ftp\|gawk\|gcc\|gcore\|gdb\|gem\|genisoimage\|ghc\|ghci\|gimp\|git\|grep\|gtester\|gzip\|hd\|head\|hexdump\|highlight\|hping3\|iconv\|iftop\|install\|ionice\|ip\|irb\|jjs\|join\|journalctl\|jq\|jrunscript\|knife\|ksh\|ksshell\|latex\|ld.so\|ldconfig\|less\|ln\|loginctl\|logsave\|look\|ltrace\|lua\|lualatex\|luatex\|lwp-download\|lwp-request\|mail\|make\|man\|mawk\|more\|mount\|msgattrib\|msgcat\|msgconv\|msgfilter\|msgmerge\|msguniq\|mtr\|mv\|mysql\|nano\|nasm\|nawk\|nc\|neofetch\|nice\|nl\|nmap\|node\|nohup\|npm\|nroff\|nsenter\|octave\|od\|openssl\|openvpn\|openvt\|paste\|pdb\|pdflatex\|pdftex\|perf\|perl\|pg\|php\|pic\|pico\|pip\|pkexec\|pkg\|pr\|pry\|psql\|puppet\|python\|rake\|readelf\|red\|redcarpet\|restic\|rev\|rlogin\|rlwrap\|rpm\|rpmquery\|rsync\|ruby\|run-mailcap\|run-parts\|rview\|rvim\|scp\|screen\|script\|sed\|service\|setarch\|sftp\|sg\|shuf\|slsh\|smbclient\|snap\|socat\|soelim\|sort\|split\|sqlite3\|ss\|ssh-keygen\|ssh-keyscan\|ssh\|start-stop-daemon\|stdbuf\|strace\|strings\|su\|sysctl\|systemctl\|systemd-resolve\|tac\|tail\|tar\|taskset\|tbl\|tclsh\|tcpdump\|tee\|telnet\|tex\|tftp\|tic\|time\|timedatectl\|timeout\|tmux\|top\|troff\|tshark\|ul\|unexpand\|uniq\|unshare\|update-alternatives\|uudecode\|uuencode\|valgrind\|vi\|view\|vigr\|vim\|vimdiff\|vipw\|virsh\|watch\|wc\|wget\|whiptail\|whois\|wish\|xargs\|xelatex\|xetex\|xmodmap\|xmore\|xxd\|xz\|yarn\|yelp\|yum\|zip\|zsh\|zsoelim\|zypper'

  # exploitable kernel versions
  # update this list with:
  # wget -q -O- https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md | grep "Kernels:\s\+" | sed 's,Kernels:\s\+\(.*\)$,\1,g' | tr -d ',' | tr ' ' '\n' | sort -u -r | sed ':a;N;$!ba;s,\n,\\|,g'
  vulnerable_kernels='3.9.6\|3.9.0\|3.9\|3.8.9\|3.8.8\|3.8.7\|3.8.6\|3.8.5\|3.8.4\|3.8.3\|3.8.2\|3.8.1\|3.8.0\|3.8\|3.7.6\|3.7.0\|3.7\|3.6.0\|3.6\|3.5.0\|3.5\|3.4.9\|3.4.8\|3.4.6\|3.4.5\|3.4.4\|3.4.3\|3.4.2\|3.4.1\|3.4.0\|3.4\|3.3\|3.2\|3.19.0\|3.16.0\|3.15\|3.14\|3.13.1\|3.13.0\|3.13\|3.12.0\|3.12\|3.11.0\|3.11\|3.10.6\|3.10.0\|3.10\|3.1.0\|3.0.6\|3.0.5\|3.0.4\|3.0.3\|3.0.2\|3.0.1\|3.0.0\|2.6.9\|2.6.8\|2.6.7\|2.6.6\|2.6.5\|2.6.4\|2.6.39\|2.6.38\|2.6.37\|2.6.36\|2.6.35\|2.6.34\|2.6.33\|2.6.32\|2.6.31\|2.6.30\|2.6.3\|2.6.29\|2.6.28\|2.6.27\|2.6.26\|2.6.25\|2.6.24.1\|2.6.24\|2.6.23\|2.6.22\|2.6.21\|2.6.20\|2.6.2\|2.6.19\|2.6.18\|2.6.17\|2.6.16\|2.6.15\|2.6.14\|2.6.13\|2.6.12\|2.6.11\|2.6.10\|2.6.1\|2.6.0\|2.4.9\|2.4.8\|2.4.7\|2.4.6\|2.4.5\|2.4.4\|2.4.37\|2.4.36\|2.4.35\|2.4.34\|2.4.33\|2.4.32\|2.4.31\|2.4.30\|2.4.29\|2.4.28\|2.4.27\|2.4.26\|2.4.25\|2.4.24\|2.4.23\|2.4.22\|2.4.21\|2.4.20\|2.4.19\|2.4.18\|2.4.17\|2.4.16\|2.4.15\|2.4.14\|2.4.13\|2.4.12\|2.4.11\|2.4.10\|2.2.24'

  # vulnerable sudo versions
  vulnerable_sudo='1\.\([0-7]\.[0-9]\+\|8\.\(1[0-9]*\|2[0-7]\)\)'

  # interesting groups
  interesting_groups="root\|sudo\|shadow\|adm\|wheel\|staff\|lxd\|lxc\|docker"

  # interesting sudo keywords
  interesting_sudo="env_keep+=LD_PRELOAD\|(\?ALL\s\?\(:\s\?ALL\)\?)\?\|NOPASSWD"
  
  # interesting parts of variable names
  interesting_varnames="USER\|ACCESS\|ID\|API\|SECRET\|TOKEN\|KEY\|CLIENT\|EMAIL\|AUTH\|PASS\|PW\|HASH\|DATABASE\|DEPLOY\|GPG\|ACCOUNT\|SID\|BUCKET\|PRIVATE\|GIT\|ENV\|SVN\|SSH\|LOG\|DEV"

  # caching /etc/passwd content
  etc_passwd_cache=`grep -v '^#\|^$' /etc/passwd`
  
  # save all users in the users variable
  users=`(echo "$etc_passwd_cache" | cut -d":" -f1) 2> /dev/null`

  # my (current user) information
  my_id=`(id || (groups | cut -d":" -f2)) 2> /dev/null`
  my_username=`whoami 2> /dev/null`
  my_homedir=`(echo "$etc_passwd_cache" | grep "^$my_username" | cut -d":" -f6) 2> /dev/null`

  # writable folders
  writable_folders="`find / -type d -writable \! \( -path "/proc/*" -o -path "/sys/*" \) 2> /dev/null`"
  
  #PATH manipulation: in debian some directory (e.g. /sbin or /usr/sbin) is not added to the path
  # this manipulation adds some known dir to the path, if it exists on the system
  OLD_PATH=$PATH
  known_good_path_dirs="/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin /usr/games /usr/local/games /snap/bin"
  path_manipulated=0
  
  OLD_IFS=$IFS
  IFS=$'\n'
  for d in $known_good_path_dirs; do
  
    if [[ -d "$d" ]] && [[ ! "$PATH" =~ $d ]]; then
      PATH="$PATH:$d"
      path_manipulated=1
    fi
  done
  IFS=$OLD_IFS

  if [ "$path_manipulated" = "1" ]; then
    render_text "warning" "Path changed to: $PATH"
  fi
}

###############
# checks
###############

script_info()
{
print_title "yellow" "INFO"

if [ "$keyword" ]; then 
  render_text "info" "Searching for the following keyword in conf, php, ini and log files" "$keyword"
fi

if [ "$report" ]; then render_text "info" "Report name" "$report"; fi

if [ "$export" ]; then render_text "info" "Export location" "$export"; fi

render_text "info" "Thorough tests" "`if [ "$thorough" ]; then echo -n "Enabled"; else echo -n "Disabled"; fi`"

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
print_title "yellow" "SYSTEM INFO"

# basic kernel info
unameinfo=`(uname -a | sed "s,\s\+\($vulnerable_kernels\),${_sed_red},g") 2> /dev/null`
if [ "$unameinfo" ]; then
  render_text "info" "Kernel information" "$unameinfo"  
fi

# kernel info
procver=`sed "s,\s\+\($vulnerable_kernels\),${_sed_red},g" /proc/version 2> /dev/null`
if [ "$procver" ]; then
  render_text "info" "Kernel information (continued)" "$procver"
fi

if (uname -a || cat /proc/version) | grep -q "\s\+\($vulnerable_kernels\)" 2> /dev/null; then
  render_text "hint" "It looks like we have an unpatched kernel" "Use '${_red}searchsploit `uname -s` Kernel `uname -r | cut -d'.' -f1-2`${_reset}' to look for kernel exploits"
fi

# search all *-release files for version info
release=`cat /etc/*-release 2> /dev/null`
if [ "$release" ]; then
  render_text "info" "Specific release information" "$release"
fi

# target hostname info
hostnamed=`hostname 2> /dev/null`
if [ "$hostnamed" ]; then
  render_text "info" "Hostname" "$hostnamed"
fi

# memory
freeinfo=`free -h 2> /dev/null`
if [ "$freeinfo" ]; then
  render_text "info" "Free and used memory in the system" "$freeinfo"
fi

# disk
dfinfo=`(df -h || lsblk) 2> /dev/null`
if [ "$dfinfo" ]; then
  render_text "info" "Disk space usage" "$dfinfo"
fi

# cpu
cpuinfo=`lscpu 2> /dev/null`
if [ "$cpuinfo" ]; then
  render_text "info" "CPU architecture" "$cpuinfo"
fi

# printers
printersinfo=`lpstat -a 2>/dev/null`
if [ "$printersinfo" ]; then
  render_text "info" "Printer(s)" "$printersinfo"
fi
}

user_info()
{
  
# if we have to export something, we prepare the destination directory
if [ "$export" ]; then
  mkdir "$format/etc-export/" 2> /dev/null
fi
  
print_title "yellow" "USER/GROUP" 

#current user details
render_text "info" "Current user/group info" \
                   "`(echo "$my_id" | sed "s,\((\|\s\)\($interesting_groups\)\()\|\s\),${_sed_cyan},g") 2> /dev/null`"

#last logged on user information
lastlogedonusrs=`(lastlog | awk "NR>1" | grep -v "Never") 2> /dev/null`
if [ "$lastlogedonusrs" ]; then
  render_text "info" "Users that have previously logged onto the system" "$lastlogedonusrs"
fi

#who else is logged on
loggedonusrs=`w 2> /dev/null`
if [ "`echo "$loggedonusrs" | wc -l`" -gt "1" ]; then
  render_text "info" "Who else is logged on" "$loggedonusrs"
fi

#lists all id's and respective group(s)
grpinfo=""
for u in $users; do
  idoutput=`( (id "$u" || (groups "$u" | cut -d":" -f2) ) | sed "s,\((\|\s\)\($interesting_groups\)\()\|\s\),${_sed_yellow},g") 2> /dev/null`
  entry="${_cyan}$u${_reset} : $idoutput"
  
  # we concatenate or init the list of processes
  if [ "$grpinfo" ]; then grpinfo="$grpinfo"$'\n'"$entry"; else grpinfo="$entry"; fi
done

if [ "$grpinfo" ]; then
  render_text "info" "Group memberships" "$grpinfo"
fi

#checks to see if any hashes are stored in /etc/passwd (deprecated *nix storage method)
hashesinpasswd=`(echo "$etc_passwd_cache" | grep -v '^[^:]\+:[^:]\?:') 2> /dev/null`
if [ "$hashesinpasswd" ]; then
  render_text "danger" "It looks like we have password hashes in /etc/passwd" "$hashesinpasswd"
fi

#checks to see if there are empty password fields in /etc/passwd
emptypassfield=`(echo "$etc_passwd_cache" | grep '^[^:]\+::') 2> /dev/null`
if [ "$emptypassfield" ]; then
  render_text "danger" "It looks like we have a user with an empty password field in /etc/passwd" "$emptypassfield"
fi

#contents of /etc/passwd
readpasswd=`(echo "$etc_passwd_cache" | sed "s/.*sh$/${_sed_yellow}/") 2> /dev/null`
if [ "$readpasswd" ]; then
  render_text "info" "Contents of /etc/passwd" "$readpasswd"

  if [ "$export" ]; then cp /etc/passwd "$format/etc-export/passwd" 2> /dev/null; fi
fi

#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow 2> /dev/null`
if [ "$readshadow" ]; then
  render_text "danger" "We can read the shadow file" "$readshadow"
  
  if [ "$export" ]; then cp /etc/shadow "$format/etc-export/shadow" 2> /dev/null; fi
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2> /dev/null`
if [ "$readmasterpasswd" ]; then
  render_text "danger" "We can read the master.passwd file" "$readmasterpasswd"

  if [ "$export" ]; then cp /etc/master.passwd "$format/etc-export/master.passwd" 2> /dev/null; fi
fi

#all root accounts (uid 0)
superman=`(echo "$etc_passwd_cache" | awk -F':' '$3 == 0 {print $1}') 2> /dev/null`
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
    sudoers=`(echo "$sudoers" | sed "s,$interesting_sudo,${_sed_red},g" | sed "s,\($interesting_binaries\)\s\+,${_sed_yellow},g") 2> /dev/null`
    render_text "warning" "We can read /etc/sudoers" "$sudoers"
    
    if [ "$export" ]; then cp /etc/sudoers "$format/etc-export/sudoers" 2> /dev/null; fi
  fi
  
  # check if we can sudo without password
  sudoperms=`(echo '' | sudo -S -l -k) 2> /dev/null`
  if [ "$sudoperms" ]; then
    sudoperms=`(echo "$sudoperms" | sed "s,$interesting_sudo,${_sed_red},g" | sed "s,\($interesting_binaries\)\s\+,${_sed_yellow},g") 2> /dev/null`
    render_text "danger" "We can 'sudo -l' without supplying a password" "$sudoperms"
  else
    if [ "$sudopass" ]; then
      # check if we can sudo with password
      sudoauth=`(echo "$userpassword" | sudo -S -l -k) 2> /dev/null`
      
      if [ "$sudoauth" ]; then
        sudoauth=`(echo "$sudoauth" | sed "s,$interesting_sudo,${_sed_red},g" | sed "s,\($interesting_binaries\)\s\+,${_sed_yellow},g") 2> /dev/null`
        render_text "danger" "We can sudo when supplying a password" "$sudoauth"
      fi
    fi
  fi

  # check for writable/readable files in /etc/sudoers.d
  sudoersd=`find /etc/sudoers.d \! -name README -type f -exec ls ${_color_flag} -lah {} + 2> /dev/null`
  if [ "$sudoersd" ]; then
    render_text "danger" "Check if we can read/write files in /etc/sudoers.d" "$sudoersd"
    
    if [ "$export" ]; then
      mkdir -p "$format/etc-export/sudoers.d/" 2> /dev/null
      cp /etc/sudoers.d/* "$format/etc-export/sudoers.d/" 2> /dev/null
    fi
  fi

  # who has sudoed in the past
  sudoerhomelist="`(find /home -name .sudo_as_admin_successful -type f -exec dirname {} + | sort -u) 2> /dev/null`"
  if [ "$sudoerhomelist" ]; then
    sudoerslist=""
    for h in $sudoerhomelist; do
      entry=`(ls -dl "$h" | awk 'NR==1 {print $3}') 2> /dev/null`
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

# we proceed with ssh checks, only if we can read /etc/ssh/sshd_config
if [ -r "/etc/ssh/sshd_config" ]; then
  ssh_interesting_keywords="PubkeyAuthentication\|AuthenticationMethods\|PermitRootLogin\|PermitEmptyPasswords\|AllowUsers\|DenyUsers"
  sshdchecks="`(grep -v '^#\|^$' /etc/ssh/sshd_config | sed "s,\($ssh_interesting_keywords\)\s\+,${_sed_yellow},g") 2> /dev/null`"
  
  if [ "$sshdchecks" ]; then
    render_text "info" "Check SSH daemon configuration (condensed)" "$sshdchecks"
  fi
  
  if [ "$export" ]; then cp /etc/ssh/sshd_config "$format/etc-export/" 2> /dev/null; fi

fi

#thorough checks
if [ "$thorough" = "1" ]; then
  #looks for files we can write to but that don't belong to us
  grfilesall=`find / -writable \! -user "$my_username" -type f \! \( -path "/proc/*" -o -path "/sys/*" \) 2> /dev/null`
  if [ "$grfilesall" ]; then
    render_text "info" "File(s) not owned by our user ($my_username) but writable" "`print_ls_lh "$grfilesall"`"
  fi

  #looks for files that belong to us
  ourfilesall=`find / -user "$my_username" -type f \! \( -path "/proc/*" -o -path "/sys/*" \) 2> /dev/null`
  if [ "$ourfilesall" ]; then
    render_text "info" "File(s) owned by our user ($my_username)" "`print_ls_lh "$ourfilesall"`"
  fi

  #looks for hidden files
  hiddenfiles=`find / -name ".*" -type f \! \( -path "/proc/*" -o -path "/sys/*" \) 2> /dev/null`
  if [ "$hiddenfiles" ]; then
    render_text "warning" "Hidden files" "`print_ls_lh "$hiddenfiles"`"
  fi
  
  # looks for world-reabable files within /home
  wrfilesinhome=`find /home/ -readable -type f 2> /dev/null`
  if [ "$wrfilesinhome" ]; then
    render_text "warning" "World-readable files within /home" "`print_ls_lh "$wrfilesinhome"`"

    if [ "$export" ]; then
      mkdir "$format/wr-files/" 2> /dev/null
      OLD_IFS=$IFS; IFS=$'\n'
      for f in $wrfilesinhome; do cp --parents "$f" "$format/wr-files/"; done 2> /dev/null
      IFS=$OLD_IFS
    fi
  fi

  # lists current user's home directory contents
  homedircontents=`ls ${_color_flag} -Rlah "$my_homedir" 2> /dev/null`
  if [ "$homedircontents" ] ; then
    render_text "info" "Home directory contents" "$homedircontents"
  fi
  
  # checks for if various ssh files (or their backups) are accessible
  sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts*" -o -name "authorized_hosts*" -o -name "authorized_keys*" \) -type f 2> /dev/null`
  if [ "$sshfiles" ]; then
    render_text "warning" "SSH keys/host information found in the following locations" "`print_ls_lh "$sshfiles"`"

    if [ "$export" ]; then
      mkdir "$format/ssh-files/" 2> /dev/null
      OLD_IFS=$IFS; IFS=$'\n'
      for f in $sshfiles; do cp --parents "$f" "$format/ssh-files/"; done 2> /dev/null
      IFS=$OLD_IFS
    fi
  fi
fi
}

environmental_info()
{
print_title "yellow" "ENVIRONMENT"

# env information (we try to highlight useful variables)
envinfo=`( (env || set) | grep -v '^LS_COLORS=' | sed "s,^.*\($interesting_varnames\).*=,${_sed_yellow},Ig" ) 2> /dev/null`
if [ "$envinfo" ]; then
  render_text "info" "Environment information" "$envinfo"
fi

# check if apparmor is present
apparmor=`aa-status 2> /dev/null`
if [ -z "$apparmor" ]; then
  apparmor=`apparmor_status 2> /dev/null`
fi

if [ "$apparmor" ]; then
  render_text "warning" "AppArmor seems to be present" "$apparmor"
  
  apparmorls=`ls -dlah /etc/apparmor* 2> /dev/null`
  if [ "$apparmorls" ]; then
    render_text "info" "AppArmor dir(s)" "$apparmorls"
  fi
fi

# check if selinux is present
sestatus=`sestatus 2> /dev/null`
if [ "$sestatus" ]; then
  render_text "info" "SELinux seems to be present" "$sestatus"
fi

# ASLR check
aslr_enabled=`cat /proc/sys/kernel/randomize_va_space 2> /dev/null`
render_text "warning" "ASLR status" "`if [ "$aslr_enabled" -eq "0" ]; then echo "disabled"; else echo "enabled"; fi`"

#current path configuration
if [ "$OLD_PATH" ]; then
  render_text "info" "PATH" "$OLD_PATH"
  
  # check if some writable folder is in the PATH
  wr_folder_in_path="";
  
  OLD_IFS=$IFS
  IFS=$'\n'
  for d in $writable_folders; do  
    if [[ -d "$d" ]] && [[ ! -L "$d" ]] && [[ "$OLD_PATH" =~ $d ]]; then
      if [ "$wr_folder_in_path" ]; then wr_folder_in_path="$wr_folder_in_path\|$d"; else wr_folder_in_path="$d"; fi
    fi
  done
  IFS=$OLD_IFS
  
  PATH_W_SPACES=`echo "$OLD_PATH" | tr ':' ' '`
  pathswriteable=`(ls -dlah $PATH_W_SPACES | sed "s,$wr_folder_in_path,${_sed_green},g") 2> /dev/null`
  if [ "$pathswriteable" ]; then
    render_text "warning" "Check if some folder of the PATH is ${_green}writable" "$pathswriteable"
  fi
fi

#lists available shells
etc_shells_content=`grep -v '^#\|^$' /etc/shells 2> /dev/null`
shellinfo=`print_ls_lh "$etc_shells_content"`
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
      mkdir "$format/etc-export/" 2> /dev/null
      cp /etc/login.defs "$format/etc-export/login.defs" 2> /dev/null
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

# caching all automated jobs/tasks files
automated_jobs=`find /etc/cron* /etc/anacron* /etc/at* /var/spool/anacron /var/spool/cron/crontabs \! -name ".placeholder" -type f 2> /dev/null`
if [ "$automated_jobs" ]; then
  # showing jobs files
  render_text "info" "Automated jobs/tasks files" "`print_ls_lh "$automated_jobs"`"
fi

if [ "$thorough" ] && [ -z "$automated_jobs" ]; then
  effective_automated_jobs=$automated_jobs
else
  effective_automated_jobs="/etc/crontab"$'\n'"/etc/anacrontab"$'\n'
fi

if [ "$effective_automated_jobs" ]; then

  automated_jobs_output=""
  writable_jobs=""
  jobs_with_path=""

  OLD_IFS=$IFS
  IFS=$'\n'
  # showing jobs content
  for f in $effective_automated_jobs; do
    automated_job_output=`grep -v '^#\|^$' "$f" 2> /dev/null`
    if [ "$automated_job_output" ]; then
      render_text "info" "$f content (condensed)" "$automated_job_output"
    fi
  done

  for f in $automated_jobs; do
    # update writable jobs
    writable_job="`find "$f" -writable 2> /dev/null`"
    if [ "$writable_jobs" ]; then writable_jobs="$writable_jobs"$'\n'"$writable_job"; else writable_jobs="$writable_job"; fi

    # update jobs with PATH
    path="`(grep '^PATH=' "$f" | sed 's,^PATH=,,' | tr ':' '\n') 2> /dev/null`"
    if [ "$path" ]; then
      wr_folder_in_path="";
      
      for d in $path; do
        if [[ -d "$d" ]] && [[ ! -L "$d" ]] && [[ "$writable_folders" =~ $d ]]; then
          if [ "$wr_folder_in_path" ]; then wr_folder_in_path="$wr_folder_in_path\|$d"; else wr_folder_in_path="$d"; fi
        fi
      done
      
      if [ "$wr_folder_in_path" ]; then
        job_with_path="`( (ls ${_color_flag} -lah "$f"; echo; sed "s,\([=:]\($wr_folder_in_path\)\)\+,${_sed_green},g" "$f"; echo) | sed "s,$f,${_sed_cyan},g" ) 2> /dev/null`"
        if [ "$jobs_with_path" ]; then jobs_with_path="$jobs_with_path"$'\n'"$job_with_path"; else jobs_with_path="$job_with_path"; fi
      fi
    fi
  done
  IFS=$OLD_IFS

  # show writable job files
  if [ "$writable_jobs" ]; then
    render_text "warning" "It looks that we can manipulate some automated job/task" "`print_ls_lh "$writable_jobs"`"
  fi

  # show writable folder in PATHs
  if [ "$jobs_with_path" ]; then
    render_text "warning" "It looks that we have some writable folder in the job PATH" "$jobs_with_path"
  fi
fi

#see if any users have associated cronjobs (priv command)
for u in $users; do
  cronother=`crontab -l -u "$u" 2> /dev/null`
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
  udpserv=`ss -lnup 2> /dev/null`
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
  OLD_IFS=$IFS; IFS=$'\n'
  for proc in $psoutput; do
    procpath="`command -v -- $proc 2> /dev/null`"
    if [ "$proclist" ]; then proclist="$proclist"$'\n'"$procpath"; else proclist="$procpath"; fi
  done
  IFS=$OLD_IFS
  
  if [ "$proclist" ]; then
    render_text "info" "Process binaries and associated permissions (from the above list)" "`ls ${_color_flag} -lah $proclist 2> /dev/null`"
  
    if [ "$export" ]; then
      mkdir "$format/ps-export/" 2> /dev/null
      OLD_IFS=$IFS; IFS=$'\n'
      for binary in $proclist; do cp --parents "$binary" "$format/ps-export/"; done 2> /dev/null
      IFS=$OLD_IFS
    fi
  fi
fi

#anything 'useful' in inetd.conf
inetdread=`grep -v '^#\|^$' /etc/inetd.conf 2> /dev/null`
if [ "$inetdread" ]; then
  render_text "info" "Contents of /etc/inetd.conf (condensed)" "$inetdread"

  if [ "$export" ]; then
    mkdir "$format/etc-export/" 2> /dev/null
    cp /etc/inetd.conf "$format/etc-export/inetd.conf" 2> /dev/null
  fi
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`awk '{print $7}' /etc/inetd.conf 2> /dev/null`
if [ "$inetdbinperms" ]; then
  render_text "info" "The related inetd binary permissions" "`print_ls_lh "$inetdbinperms"`"
fi

#check /etc/xinetd.conf file content
xinetdread=`grep -v '^#\|^$' /etc/xinetd.conf 2> /dev/null`
if [ "$xinetdread" ]; then
  render_text "info" "Contents of /etc/xinetd.conf" "$xinetdread"
  
  if [ "$export" ]; then
    mkdir "$format/etc-export/" 2> /dev/null
    cp /etc/xinetd.conf "$format/etc-export/xinetd.conf" 2> /dev/null
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
  render_text "info" "The related xinetd binary permissions" "`print_ls_lh "$xinetdbinperms"`"
fi

initdread=`ls ${_color_flag} -lah /etc/init.d 2> /dev/null`
if [ "$initdread" ]; then
  render_text "info" "/etc/init.d/ binary permissions" "$initdread"
fi

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2> /dev/null`
if [ "$initdperms" ]; then
  render_text "info" "/etc/init.d/ files not belonging to root" "`print_ls_lh "$initdperms"`"
fi

rcdread=`ls ${_color_flag} -la /etc/rc.d/init.d 2> /dev/null`
if [ "$rcdread" ]; then
  render_text "info" "/etc/rc.d/init.d binary permissions" "$rcdread"
fi

#init.d files NOT belonging to root!
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2> /dev/null`
if [ "$rcdperms" ]; then
  render_text "danger" "/etc/rc.d/init.d files not belonging to root" "`print_ls_lh "$rcdperms"`"
fi

usrrcdread=`ls ${_color_flag} -lah /usr/local/etc/rc.d 2> /dev/null`
if [ "$usrrcdread" ]; then
  render_text "info" "/usr/local/etc/rc.d binary permissions" "$usrrcdread"
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2> /dev/null`
if [ "$usrrcdperms" ]; then
  render_text "danger" "/usr/local/etc/rc.d files not belonging to root" "`print_ls_lh "$xinetdbinperms"`"
fi

initread=`ls ${_color_flag} -la /etc/init/ 2> /dev/null`
if [ "$initread" ]; then
  render_text "info" "/etc/init/ config file permissions" "$initread"
fi

# upstart scripts not belonging to root
initperms=`find /etc/init \! -uid 0 -type f 2> /dev/null`
if [ "$initperms" ]; then
   render_text "danger" "/etc/init/ config files not belonging to root" "`print_ls_lh "$initdperms"`"
fi

if [ "$thorough" = "1" ]; then
  systemdread="`find /lib/systemd/ /etc/systemd/ -type f 2> /dev/null`";
  systemdperms="`find /lib/systemd/ /etc/systemd/ \( \! -uid 0 -o -writable \) -type f 2> /dev/null`"
else
  systemdread="`find /lib/systemd/ /etc/systemd/ -name "*.service" -type f 2> /dev/null`"
  systemdperms="`find /lib/systemd/ /etc/systemd/ \( \! -uid 0 -o -writable \) -name "*.service" -type f 2> /dev/null`"
fi

# systemd files
if [ "$systemdread" ]; then
  render_text "info" "systemd config file permissions" "`print_ls_lh "$systemdread"`"
fi

# systemd files not belonging to root or writable
if [ "$systemdperms" ]; then
   render_text "danger" "systemd config files not belonging to root or writable" "`print_ls_lh "$systemdperms"`"
fi
}

software_configs()
{
print_title "yellow" "SOFTWARE"

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`(sudo -V | head -n1 | cut -d' ' -f3) 2> /dev/null`
if [ "$sudover" ]; then
  render_text "info" "Sudo version" "`echo "$sudover" | sed "s,$vulnerable_sudo,${_sed_red},"`"
  
  if echo "$sudover" | grep -q "$vulnerable_sudo" 2> /dev/null; then
    render_text "hint" "It looks like we have a vulnearble sudo version" "Use '${_red}searchsploit sudo $sudover${_reset}' to look for available exploits"
  fi
  
  
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
  mysql_usernames="root"
  if [[ ! "$mysql_usernames" =~ $my_username ]]; then mysql_usernames="$mysql_usernames"$'\n'"$my_username"; fi
  
  mysql_passwords=" "$'\n'"root"$'\n'"toor"
  if [[ ! "$mysql_passwords" =~ $my_username ]]; then mysql_passwords="$mysql_passwords"$'\n'"$my_username"; fi
  
  OLD_IFS=$IFS; IFS=$'\n'
  for u in $mysql_usernames; do
    for p in $mysql_passwords; do
      if [ "$p" != " " ]; then param="-p$p"; else param=""; fi
      
      mysqlcon=`mysqladmin -u$u ${param} version 2> /dev/null`

      if [ "$mysqlcon" ]; then
        title="We can connect to MYSQL service as $u"
        if [ "$p" != " " ]; then title="$title with password $p";
        else title="$title without password"; fi
        
        render_text "danger" "$title" "$mysqlcon"
        
        resultset=`mysql -u$u ${param} -s -e "select User,Host,Password from mysql.user;" 2> /dev/null`
        
        mysqluserout=""
        
        for row in $resultset; do
          user=`(echo "$row" | cut -f1) 2> /dev/null`
          host=`(echo "$row" | cut -f2) 2> /dev/null`
          pass=`(echo "$row" | cut -f3) 2> /dev/null`
          if [ -z "$pass" ]; then pass="(no password)"; fi
          
          entry="`echo "username: $user@$host, password (hashed): $pass" | sed "s,$user\|$host\|$pass,${_sed_red},g"`"
          if [ "$mysqluserout" ]; then mysqluserout="$mysqluserout"$'\n'"$entry"; else mysqluserout="$entry"; fi
          
        done
        
        if [ "$mysqluserout" ]; then
          render_text "warning" "credentials from mysql.user table" "$mysqluserout"
          break
        fi
      fi
      
    done
  done
  IFS=$OLD_IFS
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
      postcon=`psql -U$u -w$w -c 'select version()' 2> /dev/null | grep ${_color_flag} version`

      if [ "$postcon" ]; then
        render_text "danger" "We can connect to Postgres DB $w as user $u with no password" "$postcon"
      fi
      
    done
  done
fi

#apache details - if installed
apachever=`( (apache2 -v || httpd -v) | head -n1 | awk -F': ' '{ print $2 }' ) 2> /dev/null`
if [ "$apachever" ]; then
  render_text "info" "Apache version" "$apachever"

  #what user:group is running apache daemon?
  if [[ -f "/etc/apache2/envvars" ]]; then
    apacheusr=`(grep -i 'user' /etc/apache2/envvars | cut -d'=' -f2) 2> /dev/null`
    apachegrp=`(grep -i 'group' /etc/apache2/envvars | cut -d'=' -f2) 2> /dev/null`
    
    if [ "$apacheusr" ] && [ "$apachegrp" ]; then
      render_text "info" "Apache is running as (user:group)" "$apacheusr:$apachegrp"

      if [ "$export" ]; then
        mkdir --parents "$format/etc-export/apache2/" 2> /dev/null
        cp /etc/apache2/envvars "$format/etc-export/apache2/envvars" 2> /dev/null
      fi
    fi
  fi

  #installed apache modules
  apachemodules=`(apache2ctl -M || httpd -M) 2> /dev/null`
  if [ "$apachemodules" ]; then
    render_text "info" "Installed Apache modules" "$apachemodules"
  fi

  #htpasswd check
  htpasswd=`find / -name ".htpasswd*" -print -exec cat {} + 2> /dev/null`
  if [ "$htpasswd" ]; then
    render_text "danger" ".htpasswd found - could contain passwords" "$htpasswd"
  fi

  #anything in the default http home dirs (a thorough only check as output can be large)
  if [ "$thorough" = "1" ]; then
    apache_dirs="/var/www/ /srv/www/htdocs/ /usr/local/www/apache2/data/ /opt/lampp/htdocs/"
    apachehomedirs=`ls ${_color_flag} -Rlah $apache_dirs 2> /dev/null`
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
bin_of_interest="nc netcat ncat socat wget curl ftp nmap ping gcc gdb perl php ruby python python2 python3"
bin_fullpath=`command -v $bin_of_interest 2> /dev/null`
if [ "$bin_fullpath" ]; then
  render_text "info" "Useful utilities" "`print_ls_lh "$bin_fullpath"`"
fi

#limited search for installed compilers
compiler=`( (dpkg --list | grep '\s\+compiler') || (yum list installed 'gcc*' | grep gcc) ) 2> /dev/null`
if [ "$compiler" ]; then
  render_text "info" "Installed compilers" "$compiler"
fi

#manual check - lists out sensitive files, can we read/modify etc.
sensitive_files="/etc/passwd
/etc/group
/etc/profile
/etc/shadow
/etc/master.passwd
/etc/security/opasswd"
render_text "warning" "Check if we can read/write sensitive files" "`print_ls_lh "$sensitive_files"`"

# regular files that have changed in the last 10 minutes
changedfiles=`find / -mmin 10 \! \( -path "/proc/*" -o -path "/sys/*" \) -type f 2> /dev/null`
if [ "$changedfiles" ]; then
  render_text "warning" "Regular files that have changed in the last 10 minutes" "`print_ls_lh "$changedfiles"`"
fi

#search for suid files
allsuid=`find / -perm -4000 -type f 2> /dev/null`
if [ "$allsuid" ]; then
  allsuiddetails="`print_ls_lh "$allsuid"`"
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
    render_text "warning" "World-writable SUID files" "`print_ls_lh "$wwsuid"`"
  fi

  #lists world-writable suid files owned by root
  wwrootsuid=`find $allsuid -uid 0 -perm -4002 -type f 2> /dev/null`
  if [ "$wwrootsuid" ]; then
    render_text "warning" "World-writable SUID files owned by root" "`print_ls_lh "$wwrootsuid"`"
  fi

  if [ "$export" ]; then
    mkdir "$format/suid-files/" 2> /dev/null
    OLD_IFS=$IFS; IFS=$'\n'
    for f in $allsuid; do cp "$f" "$format/suid-files/"; done 2> /dev/null
    IFS=$OLD_IFS
  fi
fi

#search for sgid files
allsgid=`find / -perm -2000 -type f 2> /dev/null`
if [ "$allsgid" ]; then
  allsgiddetails="`print_ls_lh "$allsgid"`"
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
    render_text "warning" "World-writable SGID files" "`print_ls_lh "$wwsgid"`"
  fi

  #lists world-writable sgid files owned by root
  wwrootsgid=`find $allsgid -uid 0 -perm -2002 -type f 2> /dev/null`
  if [ "$wwrootsgid" ]; then
    render_text "warning" "World-writable SGID files owned by root" "`print_ls_lh "$wwrootsgid"`"
  fi
  
  if [ "$export" ]; then
    mkdir "$format/sgid-files/" 2> /dev/null
    OLD_IFS=$IFS; IFS=$'\n'
    for f in $allsgid; do cp "$f" "$format/sgid-files/"; done 2> /dev/null
    IFS=$OLD_IFS
  fi
fi

#list all files with POSIX capabilities set along with there capabilities
fileswithcaps=`(getcap -r / || /sbin/getcap -r /) 2> /dev/null`
if [ "$fileswithcaps" ]; then
  render_text "info" "Files with POSIX capabilities set" "$fileswithcaps"
  
  if [ "$export" ]; then
    mkdir "$format/files_with_capabilities/" 2> /dev/null
    OLD_IFS=$IFS; IFS=$'\n'
    for f in $fileswithcaps; do cp "$f" "$format/files_with_capabilities/"; done 2> /dev/null
    IFS=$OLD_IFS
  fi
fi

#searches /etc/security/capability.conf for users associated capapilies
userswithcaps=`grep -v '^#\|none\|^$' /etc/security/capability.conf 2> /dev/null`
if [ "$userswithcaps" ]; then
  render_text "info" "Users with specific POSIX capabilities" "$userswithcaps"

  #matches the capabilities found associated with users with the current user
  matchedcaps=`(echo -e "$userswithcaps" | grep "$my_username" | awk '{print $1}') 2> /dev/null`
  if [ "$matchedcaps" ]; then
    render_text "info" "Capabilities associated with the current user" "$matchedcaps"

    #matches the files with capapbilities with capabilities associated with the current user
    matchedfiles=`(echo -e "$matchedcaps" | while read -r cap; do echo -e "$fileswithcaps" | grep "$cap"; done) 2> /dev/null`
    if [ "$matchedfiles" ]; then
      render_text "warning" "Files with the same capabilities associated with the current user (You may want to try abusing those capabilties)" "$matchedfiles"
      
      #lists the permissions of the files having the same capabilies associated with the current user
      matchedfilesperms=`(echo -e "$matchedfiles" | awk '{print $1}') 2> /dev/null`
      render_text "info" "Permissions of files with the same capabilities associated with the current user" "`print_ls_lh "$matchedfilesperms"`"
      
      if [ "$matchedfilesperms" ]; then
        #checks if any of the files with same capabilities associated with the current user is writable
        writablematchedfiles=`(echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do find "$f" -writable; done) 2> /dev/null`
        if [ "$writablematchedfiles" ]; then
          render_text "info" "User/Group writable files with the same capabilities associated with the current user" "`print_ls_lh "$writablematchedfiles"`"
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
  wwfiles=`find / \! \( -path "/proc/*" -o -path "/sys/*" \) -writable -type f -exec ls ${_color_flag} -lah {} + 2> /dev/null`
  if [ "$wwfiles" ]; then
    render_text "info" "World-writable files (excluding /proc and /sys)" "$wwfiles"

    if [ "$export" ]; then
      mkdir "$format/ww-files/" 2> /dev/null
      OLD_IFS=$IFS; IFS=$'\n'
      for f in $wwfiles; do cp --parents "$f" "$format/ww-files/"; done 2> /dev/null
      IFS=$OLD_IFS
	  fi
  fi

fi

usrplans_or_usrrhosts="`find /home /usr/home -name "*.plan" -o -name "*.rhosts" -type f 2> /dev/null`"
if [ "$usrplans_or_usrrhosts" ]; then

  #are any .plan files accessible in /home (could contain useful information)
  usrplans="`(echo "$usrplans_or_usrrhosts" | grep -i '.plan') 2> /dev/null`"
  if [ "$usrplans" ]; then

    usrplan_output=""
    OLD_IFS=$IFS; IFS=$'\n'
    for f in $usrplans; do
      usrplan="`( (ls ${_color_flag} -lah "$f"; echo; cat "$f"; echo) | sed "s,$f,${_sed_cyan},g" ) 2> /dev/null`"
      if [ "$usrplan_output" ]; then usrplan_output="$usrplan_output"$'\n'"$usrplan"; else usrplan_output="$usrplan"; fi
    done

    if [ "$usrplan_output" ]; then
      render_text "warning" "Plan file permissions and contents" "$usrplan_output"
    fi
    
    if [ "$export" ]; then
      mkdir "$format/plan_files/" 2> /dev/null
      for f in $usrplan; do cp --parents "$f" "$format/plan_files/"; done 2> /dev/null
    fi
    
    IFS=$OLD_IFS
  fi

  #are there any .rhosts files accessible - these may allow us to login as another user etc.
  usrrhosts="`(echo "$usrplans_or_usrrhosts" | grep -i '.rhosts') 2> /dev/null`"
  if [ "$usrrhosts" ]; then

    usrrhost_output=""
    OLD_IFS=$IFS; IFS=$'\n'
    for f in $usrrhosts; do
      usrrhost="`( (ls ${_color_flag} -lah "$f"; echo; cat "$f"; echo) | sed "s,$f,${_sed_cyan},g" ) 2> /dev/null`"
      if [ "$usrrhost_output" ]; then usrrhost_output="$usrrhost_output"$'\n'"$usrrhost"; else usrrhost_output="$usrrhost"; fi
    done
    
    if [ "$usrrhost_output" ]; then
      render_text "warning" "rhost config file(s) and file contents" "$usrrhost_output"
    fi
    
    if [ "$export" ]; then
      mkdir "$format/rhosts/" 2> /dev/null
      for f in $rhostsusr; do cp --parents "$f" "$format/rhosts/"; done 2> /dev/null
    fi
    
    IFS=$OLD_IFS
    
  fi
  
fi

rhostssys="`find /etc -iname hosts.equiv -exec ls ${_color_flag} -lah {} \; -exec cat {} \; 2> /dev/null`"
if [ "$rhostssys" ]; then
  render_text "info" "hosts.equiv file and contents" "$rhostssys"

  if [ "$export" ]; then
    mkdir "$format/rhosts/" 2> /dev/null
    OLD_IFS=$IFS; IFS=$'\n'
    for f in $rhostssys; do cp --parents "$f" "$format/rhosts/"; done 2> /dev/null
    IFS=$OLD_IFS
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
    mkdir "$format/etc-export/" 2> /dev/null
    cp /etc/exports "$format/etc-export/exports" 2> /dev/null
  fi
fi

#looking for credentials in /etc/fstab and /etc/mtab
tabfiles="/etc/fstab /etc/mtab"
OLD_IFS=$IFS
IFS=$'\n'
for f in $tabfiles; do
  [[ -e "$f" ]] || continue
  
  tabcreds=`grep "\(credentials\|login\|user\(name\)\?\|pass\(word\)\?\|pwd\?\)[=]" "$f" 2> /dev/null`
  if [ "$tabcreds" ]; then
    render_text "warning" "Look for possible credentials in $f" "`cat "$f" 2> /dev/null`"
  else
    if [ "$thorough" = "1" ]; then
      render_text "info" "NFS displaying partitions and filesystems - you need to look for exotic filesystems" "$f"
    fi
  fi
  
  if [ "$export" ]; then
    mkdir "$format/etc-exports/" 2> /dev/null
    cp "$f" "$format/etc-exports/" 2> /dev/null
  fi
  
done
IFS=$OLD_IFS

#can we read some log?
readablelogs=`find /etc/log /var/log -type f -name "*log*" -readable -exec ls -l {} + 2> /dev/null`
if [ "$readablelogs" ]; then
  render_text "warning" "We can read these log files content" "$readablelogs"
fi

if [ "$keyword" ]; then
  # first of all get all files
  keyfiles="`find / -maxdepth 4 \( \! -name "*example" -a \( -name "*.conf*" -o -name "*.cnf*"  -o -name "*.log*" -o -name "*.ini*" \) \) -type f 2> /dev/null`"
  phpkeyfiles="`find / -maxdepth 10 \( -name "*.php*" -o -name "*.py*" \) -type f 2> /dev/null`"
  
  if [ "$phpkeyfiles" ]; then
    keyfiles="$keyfiles\n$phpkeyfiles"
  fi
  
  if [ "$keyfiles" ]; then
    OLD_IFS=$IFS
    IFS=$'\n'
    keyfilesoutput=""
    for f in $keyfiles; do
      entry="`grep -Hn "$keyword" "$f" 2> /dev/null`"
      if [ "$keyfilesoutput" ]; then keyfilesoutput="$keyfilesoutput"$'\n'"$entry"; else keyfilesoutput="$entry"; fi
    done
    IFS=$OLD_IFS
    
    if [ "$keyfilesoutput" ]; then
      render_text "warning" "Find keyword ($keyword) in *.php, *.conf, etc. files (output format filepath:identified line number where keyword appears)" "$keyfilesoutput"
      
      if [ "$export" ]; then
        mkdir --parents "$format/keyword_file_matches/" 2> /dev/null
        OLD_IFS=$IFS
        IFS=$'\n'
        for f in $keyfiles; do cp --parents "$f" "$format/keyword_file_matches/"; done 2> /dev/null
        IFS=$OLD_IFS
      fi
    fi
  fi
fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 \( -name "*.conf" -a \! -name "*example" \) -type f -exec ls ${_color_flag} -lah {} + 2> /dev/null`
if [ "$allconf" ]; then
  render_text "info" "All *.conf files in /etc (recursive 1 level)" "$allconf"

  if [ "$export" ]; then
    mkdir "$format/conf-files/" 2> /dev/null
    OLD_IFS=$IFS; IFS=$'\n'
    for f in $allconf; do cp --parents "$f" "$format/conf-files/"; done 2> /dev/null
    IFS=$OLD_IFS
  fi
fi

# retrieves accessible history file paths (e.g. ~/.bash_history, ~/.wget-hsts, ~/.lesshst, ecc.)
# from users with valid home directories and shells
for entry in `(echo "$etc_passwd_cache" | grep "^.*sh$") 2> /dev/null`; do
  user=`echo "$entry" | cut -d":" -f1`
  home=`echo "$entry" | cut -d":" -f6`
  usrhist=`ls ${_color_flag} -lah "$home/.*_history" "$home/.*-hsts" "$home/.*hst" 2> /dev/null`

  if [ "$usrhist" ]; then
    render_text "warning" "${user}'s history files" "$usrhist"

    # if requested we export history files
    if [ "$export" ]; then
      # create dir only if it does not exist
        mkdir -p "$format/history_files/" 2> /dev/null
        OLD_IFS=$IFS; IFS=$'\n'
        for f in $usrhist; do cp --parents "$f" "$format/history_files/"; done 2> /dev/null
        IFS=$OLD_IFS
    fi
  fi
done

#all accessible .bash_history files in /home
checkbashhist=`find /home -name .bash_history -exec ls ${_color_flag} -lah {} \; -exec tail -n 30 {} \;  2> /dev/null`
if [ "$checkbashhist" ]; then
  render_text "info" "Location and contents (last 30 rows, if accessible) of .bash_history file(s)" "$checkbashhist"
fi

#hijack tmux session
tmux_installed=`command -v tmux 2> /dev/null`
if [ "$tmux_installed" ]; then
  # look for readable access to the tmux socket
  tmux_sessions=`find /var/tmp/tmux-*/default /tmp/tmux-*/default -type f -readable -exec ls ${_color_flag} -lah {} + 2> /dev/null`
  if [ "$tmux_sessions" ]; then
    render_text "danger" "Possible tmux session hijacking" "$tmux_sessions"
  fi
  
fi

#any bakup file that may be of interest
bakfiles="`find / \( -name "*.bak" -o -name "*.tmp" -o -name "*.temp" -o -name "*.old" -o -name "*.001" -o -name "*~" \) -type f -exec ls -lah {} + 2> /dev/null`"
if [ "$bakfiles" ]; then
  render_text "info" "Location and Permissions (if accessible) of backup file(s)" "`echo "$bakfiles" | sed "s,^.*\($interesting_varnames\).*,${_sed_yellow},Ig"`"
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
    mkdir "$format/mail-from-root/" 2> /dev/null
    cp "$readmailroot" "$format/mail-from-root/" 2> /dev/null
  fi
fi
}

docker_checks()
{
print_title "yellow" "DOCKER CHECKS"
#specific checks - check to see if we're in a docker container
dockercontainer=`( grep -i docker /proc/self/cgroup; 
                   find / -name "*dockerenv*" \! \( -path "*/proc/*" -o -path "/sys/*" \) -exec ls ${_color_flag} -lah {} + ) 2> /dev/null`
if [ "$dockercontainer" ]; then
  render_text "warning" "It looks like we're in a Docker container" "$dockercontainer"
fi

#specific checks - check to see if we're a docker host
dockerhost=`(docker --version; docker ps -a) 2> /dev/null`
if [ "$dockerhost" ]; then
  render_text "info" "It looks like we're hosting Docker" "$dockerhost"
fi

#specific checks - are we a member of the docker group
if (echo "$my_id" | grep -q "\((\|\s\)\(docker\)\()\|\s\)") 2> /dev/null; then
  render_text "warning" "We're a member of the (docker) group" \
                        "`(echo "$my_id" | sed "s,\((\|\s\)\(docker\)\()\|\s\),${_sed_yellow},g") 2> /dev/null`"
fi

#specific checks - are there any docker files present
dockerfiles=`find / \( -name "Dockerfile*" -o -name "docker-compose.yml*" \) -type f -exec ls ${_color_flag} -lah {} + 2> /dev/null`
if [ "$dockerfiles" ]; then
  render_text "warning" "Checks for Dokerfile(s) and docker-compose.yml(s)" "$dockerfiles"
fi

# check if we can access some docker socket
dockersock=`find / \! \( -path "/proc/*" -o -path "/sys/*" \) -type s -name "docker.sock*" -exec \ ls -lah {} + 2> /dev/null`
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
if (echo "$my_id" | grep -q '\((\|\s\)\(lxd\|lxc\)\()\|\s\)') 2> /dev/null; then
  render_text "warning" "We're a member of the (lxc/lxd) group" \
                        "`(echo "$my_id" | sed "s,\((\|\s\)\(lxd\|lxc\)\()\|\s\),${_sed_yellow},g") 2> /dev/null`"
fi
}

call_each()
{
  banner
  script_info
  
  # load common data
  common
  
  # head
  start_epoch=`date +%s`
  print_title "green" "Scan started at `date +%R`"

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
  seconds=`expr "$end_epoch" - "$start_epoch"`
  print_title "green" "Scan ended at `date +%R` (completed in $seconds secs)"
}

while getopts "qCstk:r:e:h" option; do
  case "${option}" in
    q) quiet=1;;
    C) _reset=""; _red=""; _green=""; _yellow=""; _cyan=""; _purple=""; _gray=""; _color_flag=""
       _sed_red="\o033[4m&\o033[0m"; _sed_green="\o033[4m&\o033[0m"
       _sed_yellow="\o033[4m&\o033[0m"; _sed_cyan="\o033[4m&\o033[0m"
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

if [ -z "$report" ]; then
  call_each
else
  call_each | tee -a "$report" 2> /dev/null
  sed -i 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' "$report" 2> /dev/null
fi
#EndOfScript
