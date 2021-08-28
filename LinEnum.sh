#!/bin/bash
#A script to enumerate local information from a Linux host
version="version 0.982"
#@rebootuser

# colored output vars
_reset="\e[00m"
_red="\e[00;31m"
_green="\e[00;32m"
_yellow="\e[00;33m"
_purple="\e[00;35m"
_cyan="\e[00;36m"
_gray="\e[0;37m"
_color_flag="--color"


# util functions

# usage: render_text("keyword", "value", "category")
render_text()
{
  case "$3" in
    "info") bullet="[-]"; keyword_color="${_cyan}"; value_color="";;
    "danger") bullet="[!]"; keyword_color="${_red}"; value_color="${_yellow}";;
    "warning") bullet="[!]"; keyword_color="${_yellow}"; value_color="";;
    "success") bullet="[+]"; keyword_color=""; value_color="${_green}";;
  esac
  
  echo -e "${_gray}$bullet${_reset} ${keyword_color}$1${_reset}${_gray}:${_reset}\n${value_color}$2${_reset}\n"
}

header()
{
echo -e "${_red}
#########################################################
# ${_yellow}Local Linux Enumeration & Privilege Escalation Script ${_red}#
#########################################################
# ${_yellow}www.rebootuser.com${_red}
# ${_yellow}$version${_reset}\n"
}

#help function
usage ()
{ 
header
echo -e "${_yellow}# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t ${_reset}\n
OPTIONS:
-k	Enter keyword
-e	Enter export location
-s 	Supply user password for sudo checks (INSECURE)
-t	Include thorough (lengthy) tests
-r	Enter report name
-C	Disable colored output
-h	Displays this help text

${_yellow}Running with no options = limited scans/no output file${_red}
		
#########################################################${_reset}\n"
}

debug_info()
{
echo "[-] Debug Info" 

if [ "$keyword" ]; then 
	echo -e "${_yellow}[+] Searching for the keyword ${_red}$keyword ${_yellow}in conf, php, ini and log files${_reset}\n"
fi

if [ "$report" ]; then 
	echo -e "${_yellow}[+] Report name = ${_reset}$report\n" 
fi

if [ "$export" ]; then 
	echo -e "${_yellow}[+] Export location = ${_reset}$export\n" 
fi

echo -e -n "${_yellow}[+] Thorough tests = ${_reset}"
if [ "$thorough" ]; then echo "Enabled"; else echo "Disabled"; fi
echo

sleep 2

if [ "$export" ]; then
  mkdir "$export" 2> /dev/null
  format=$export/LinEnum-export-`date +"%d-%m-%y"`
  mkdir "$format" 2> /dev/null
fi

if [ "$sudopass" ]; then 
  echo -e "${_purple}[+] Please enter password - INSECURE - really only for CTF use!${_reset}"
  read -s -r userpassword
  echo 
fi

echo -e "${_yellow}[+] Scan started at: ${_red}`date`${_reset}\n"
}

# useful binaries (thanks to https://gtfobins.github.io/)
binarylist='ansible-playbook\|apt-get\|apt\|ar\|aria2c\|arj\|arp\|ash\|at\|atobm\|awk\|base32\|base64\|basenc\|bash\|bpftrace\|bridge\|bundler\|busctl\|busybox\|byebug\|c89\|c99\|cancel\|capsh\|cat\|certbot\|check_by_ssh\|check_cups\|check_log\|check_memory\|check_raid\|check_ssl_cert\|check_statusfile\|chmod\|chown\|chroot\|cmp\|cobc\|column\|comm\|composer\|cowsay\|cowthink\|cp\|cpan\|cpio\|cpulimit\|crash\|crontab\|csh\|csplit\|csvtool\|cupsfilter\|curl\|cut\|dash\|date\|dd\|dialog\|diff\|dig\|dmesg\|dmidecode\|dmsetup\|dnf\|docker\|dpkg\|dvips\|easy_install\|eb\|ed\|emacs\|env\|eqn\|ex\|exiftool\|expand\|expect\|facter\|file\|find\|finger\|flock\|fmt\|fold\|ftp\|gawk\|gcc\|gdb\|gem\|genisoimage\|ghc\|ghci\|gimp\|git\|grep\|gtester\|gzip\|hd\|head\|hexdump\|highlight\|hping3\|iconv\|iftop\|install\|ionice\|ip\|irb\|jjs\|join\|journalctl\|jq\|jrunscript\|knife\|ksh\|ksshell\|latex\|ld.so\|ldconfig\|less\|ln\|loginctl\|logsave\|look\|ltrace\|lua\|lualatex\|luatex\|lwp-download\|lwp-request\|mail\|make\|man\|mawk\|more\|mount\|msgattrib\|msgcat\|msgconv\|msgfilter\|msgmerge\|msguniq\|mtr\|mv\|mysql\|nano\|nawk\|nc\|nice\|nl\|nmap\|node\|nohup\|npm\|nroff\|nsenter\|octave\|od\|openssl\|openvpn\|openvt\|paste\|pdb\|pdflatex\|pdftex\|perl\|pg\|php\|pic\|pico\|pip\|pkexec\|pkg\|pr\|pry\|psql\|puppet\|python\|rake\|readelf\|red\|redcarpet\|restic\|rev\|rlogin\|rlwrap\|rpm\|rpmquery\|rsync\|ruby\|run-mailcap\|run-parts\|rview\|rvim\|scp\|screen\|script\|sed\|service\|setarch\|sftp\|sg\|shuf\|slsh\|smbclient\|snap\|socat\|soelim\|sort\|split\|sqlite3\|ss\|ssh-keygen\|ssh-keyscan\|ssh\|start-stop-daemon\|stdbuf\|strace\|strings\|su\|sysctl\|systemctl\|systemd-resolve\|tac\|tail\|tar\|taskset\|tbl\|tclsh\|tcpdump\|tee\|telnet\|tex\|tftp\|tic\|time\|timedatectl\|timeout\|tmux\|top\|troff\|tshark\|ul\|unexpand\|uniq\|unshare\|update-alternatives\|uudecode\|uuencode\|valgrind\|vi\|view\|vigr\|vim\|vimdiff\|vipw\|virsh\|watch\|wc\|wget\|whois\|wish\|xargs\|xelatex\|xetex\|xmodmap\|xmore\|xxd\|xz\|yarn\|yelp\|yum\|zip\|zsh\|zsoelim\|zypper'

system_info()
{
echo -e "${_yellow}### SYSTEM ##############################################${_reset}" 

#basic kernel info
unameinfo=`uname -a 2> /dev/null`
if [ "$unameinfo" ]; then
  render_text "Kernel information" "$unameinfo" "info"
fi

procver=`cat /proc/version 2> /dev/null`
if [ "$procver" ]; then
  render_text "Kernel information (continued)" "$procver" "info"
fi

#search all *-release files for version info
release=`cat /etc/*-release 2> /dev/null`
if [ "$release" ]; then
  render_text "Specific release information" "$release" "info"
fi

#target hostname info
hostnamed=`hostname 2> /dev/null`
if [ "$hostnamed" ]; then
  render_text "Hostname" "$hostnamed" "info"
fi
}

user_info()
{
echo -e "${_yellow}### USER/GROUP ##########################################${_reset}" 

#current user details
currusr=`id 2> /dev/null`
if [ "$currusr" ]; then
  render_text "Current user/group info" "$currusr" "info"
fi

#last logged on user information
lastlogedonusrs=`lastlog 2> /dev/null | grep -v "Never" 2> /dev/null`
if [ "$lastlogedonusrs" ]; then
  render_text "Users that have previously logged onto the system" "$lastlogedonusrs" "info"
fi

#who else is logged on
loggedonusrs=`w 2> /dev/null`
if [ "$loggedonusrs" ]; then
  render_text "Who else is logged on" "$loggedonusrs" "info"
fi

# save all users in the users variable
users=`grep -v '^#' /etc/passwd 2> /dev/null | cut -d":" -f1 2> /dev/null`

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
  render_text "Group memberships" "$grpinfo" "info"
fi

#checks to see if any hashes are stored in /etc/passwd (deprecated *nix storage method)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2> /dev/null`
if [ "$hashesinpasswd" ]; then
  render_text "It looks like we have password hashes in /etc/passwd" "$hashesinpasswd" "danger"
fi

#contents of /etc/passwd
readpasswd=`cat /etc/passwd 2> /dev/null`
if [ "$readpasswd" ]; then
  render_text "Contents of /etc/passwd" "$readpasswd" "info"

  if [ "$export" ]; then
    mkdir $format/etc-export/ 2>/dev/null
    cp /etc/passwd $format/etc-export/passwd 2> /dev/null
  fi
fi

#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow 2> /dev/null`
if [ "$readshadow" ]; then
  render_text "We can read the shadow file" "$readshadow" "danger"
  
  if [ "$export" ]; then
    mkdir $format/etc-export/ 2>/dev/null
    cp /etc/shadow $format/etc-export/shadow 2> /dev/null
  fi
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  render_text "We can read the master.passwd file" "$readmasterpasswd" "danger"

  if [ "$export" ]; then
    mkdir $format/etc-export/ 2> /dev/null
    cp /etc/master.passwd $format/etc-export/master.passwd 2> /dev/null
  fi
fi

#all root accounts (uid 0)
superman=`grep -v '^#' /etc/passwd 2> /dev/null | awk -F':' '$3 == 0 {print $1}' 2> /dev/null`
if [ "$superman" ]; then
  render_text "Super user account(s)" "$superman" "warning"
fi

# we proceed with sudo checks, only if we can get the sudo binary path
sudobin=`which sudo`
if [ "$sudobin" ]; then

  #pull out vital sudoers info
  sudoers=`grep -v '^#' /etc/sudoers 2> /dev/null | grep -v '^$' 2> /dev/null`
  if [ "$sudoers" ]; then
    render_text "Sudoers configuration (condensed)" "$sudoers" "warning"

    if [ "$export" ]; then
      mkdir $format/etc-export/ 2> /dev/null
      cp /etc/sudoers $format/etc-export/sudoers 2> /dev/null
    fi
  fi

  #can we sudo without supplying a password?
  sudoperms=`echo '' | sudo -S -l -k 2> /dev/null`
  if [ "$sudoperms" ]; then
    render_text "We can sudo without supplying a password" "$sudoperms" "danger"

    #known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values)
    sudopwnage=`echo "$sudoperms" | xargs -n 1 2> /dev/null | sed 's/,*$//g' 2> /dev/null | grep -w $binarylist 2> /dev/null`
    if [ "$sudopwnage" ]; then
      render_text "Possible sudo pwnage" "$sudopwnage" "danger"
    fi

  else
    
    if [ "$sudopass" ]; then
      #can we sudo when supplying a password?
      sudoauth=`echo $userpassword | sudo -S -l -k 2> /dev/null`
      if [ "$sudoauth" ]; then
        render_text "We can sudo when supplying a password" "$sudoauth" "danger"

        #known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values) - authenticated
        sudopermscheck=`echo "$sudoauth" | xargs -n 1 2> /dev/null | sed 's/,*$//g' 2> /dev/null | grep -w $binarylist 2> /dev/null`
        if [ "$sudopermscheck" ]; then
          render_text "Possible sudo pwnage" "$sudopermscheck" "danger"
        fi

      fi
      
    fi
  fi

  #who has sudoed in the past
  sudoerhomelist=`find /home -name .sudo_as_admin_successful -exec dirname {} \; 2> /dev/null | sort -u`
  if [ "$sudoerhomelist" ]; then
    sudoerslist=""
    for h in $sudoerhomelist; do
      entry=`ls -dl "$h" 2> /dev/null | awk 'NR==1 {print $3}' 2> /dev/null`
      if [ "$sudoerslist" ]; then sudoerslist="$sudoerslist"$'\n'"$entry"; else sudoerslist="$entry"; fi
    done
    
    if [ "$sudoerslist" ]; then
        render_text "Users that have recently used sudo" "$sudoerslist" "info"
    fi
  fi

fi

#checks to see if roots home directory is accessible
rthmdir=`ls ${_color_flag} -ahl /root/ 2> /dev/null`
if [ "$rthmdir" ]; then
  render_text "We can read root's home directory" "$rthmdir" "danger"
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls ${_color_flag} -ahl /home/ 2> /dev/null`
if [ "$homedirperms" ]; then
  render_text "Are permissions on /home directories lax" "$homedirperms" "info"
fi

#is root permitted to login via ssh
sshrootlogin=`grep '^\s*PermitRootLogin\s\+' /etc/ssh/sshd_config 2> /dev/null | cut -d' ' -f2`
if [ "$sshrootlogin" = "yes" ]; then
  render_text "Root is allowed to login via SSH" "${sshrootlogin}" "info"
fi

#thorough checks
if [ "$thorough" = "1" ]; then
  current_user=`whoami`
  
  #looks for files we can write to that don't belong to us
  grfilesall=`find / -writable ! -user $current_user -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2> /dev/null`
  if [ "$grfilesall" ]; then
    render_text "Files not owned by user but writable by group" "$grfilesall" "info"
  fi

  #looks for files that belong to us
  ourfilesall=`find / -user $current_user -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2> /dev/null`
  if [ "$ourfilesall" ]; then
    render_text "Files owned by our user" "$ourfilesall" "info"
  fi

  #looks for hidden files
  hiddenfiles=`find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2> /dev/null`
  if [ "$hiddenfiles" ]; then
    render_text "Hidden files" "$hiddenfiles" "warning"
  fi
  
  #looks for world-reabable files within /home
  # depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
  wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2> /dev/null`
  if [ "$wrfileshm" ]; then
    render_text "World-readable files within /home" "$wrfileshm" "warning"

    if [ "$export" ]; then
      mkdir $format/wr-files/ 2> /dev/null
      for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2> /dev/null
    fi
  fi

  #lists current user's home directory contents
  current_user_homedir=`cat /etc/passwd | grep "^$current_user" | cut -d':' -f6`
  homedircontents=`ls ${_color_flag} -ahl "$current_user_homedir" 2> /dev/null`
  if [ "$homedircontents" ] ; then
    render_text "Home directory contents" "$homedircontents" "info"
  fi

  #checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
  sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2> /dev/null \;`
  if [ "$sshfiles" ]; then
    render_text "SSH keys/host information found in the following locations" "$sshfiles" "danger"
    
    if [ "$export" ]; then
      mkdir $format/ssh-files/ 2>/dev/null
      for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
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
  render_text "Environment information" "$envinfo" "info"
fi

#check if selinux is enabled
sestatus=`sestatus 2> /dev/null`
if [ "$sestatus" ]; then
  render_text "SELinux seems to be present" "$sestatus" "info"
fi

#phackt

#current path configuration
pathinfo=`echo $PATH 2> /dev/null`
if [ "$pathinfo" ]; then
  pathswriteable=`ls ${_color_flag} -dl $(echo $PATH | tr ":" " ")`
  render_text "Path information" "$pathinfo\n\n$pathswriteable" "info"
fi

#lists available shells
shellinfo=`ls ${_color_flag} -dl $(grep -v '^#\|^$' /etc/shells 2> /dev/null) 2> /dev/null`
if [ "$shellinfo" ]; then
  render_text "Available shells as specified in /etc/shells" "$shellinfo" "info"
fi

#current umask value with both octal and symbolic output
umaskvalue=`umask -S 2>/dev/null & umask 2> /dev/null`
if [ "$umaskvalue" ]; then
  render_text "Current umask value" "$umaskvalue" "info"
fi

#umask value as in /etc/login.defs
umaskdef=`grep ${_color_flag} -i "^UMASK" /etc/login.defs 2> /dev/null`
if [ "$umaskdef" ]; then
  render_text "umask value as specified in /etc/login.defs" "$umaskdef" "info"
fi

#password policy information as stored in /etc/login.defs
logindefs=`grep ${_color_flag} "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2> /dev/null`
if [ "$logindefs" ]; then
  render_text "Password and storage information" "$logindefs" "info"

  if [ "$export" ]; then
    mkdir $format/etc-export/ 2>/dev/null
    cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
  fi
fi
}

job_info()
{
echo -e "${_yellow}### JOBS/TASKS ##########################################${_reset}" 

#are there any cron jobs configured
cronjobs=`ls ${_color_flag} -la /etc/cron* 2> /dev/null`
if [ "$cronjobs" ]; then
  render_text "Cron jobs" "$cronjobs" "info"
fi

#can we manipulate these jobs in any way
cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2> /dev/null \;`
if [ "$cronjobwwperms" ]; then
  render_text "World-writable cron jobs and file contents" "$cronjobwwperms" "info"
fi

#contab contents
crontabvalue=`cat /etc/crontab 2> /dev/null`
if [ "$crontabvalue" ]; then
  render_text "Crontab contents" "$crontabvalue" "info"
fi

crontabvar=`ls ${_color_flag} -la /var/spool/cron/crontabs 2> /dev/null`
if [ "$crontabvar" ]; then
  render_text "Anything interesting in /var/spool/cron/crontabs" "$crontabvar" "info"
fi

anacronjobs=`ls ${_color_flag} -la /etc/anacrontab 2> /dev/null; cat /etc/anacrontab 2> /dev/null`
if [ "$anacronjobs" ]; then
  render_text "Anacron jobs and associated file permissions" "$anacronjobs" "info"
fi

anacrontab=`ls ${_color_flag} -la /var/spool/anacron 2> /dev/null`
if [ "$anacrontab" ]; then
  render_text "When were jobs last executed (/var/spool/anacron contents)" "$anacrontab" "info"
fi

#see if any users have associated cronjobs (priv command)
cronother=`echo $users | xargs -n1 crontab -l -u 2> /dev/null`
if [ "$cronother" ]; then
  render_text "Jobs held by all users" "$cronother" "info"
fi

# list systemd timers
if [ "$thorough" = "1" ]; then
  # include inactive timers in thorough mode
  systemdtimers=`systemctl list-timers --all 2> /dev/null`
else
  systemdtimers=`systemctl list-timers 2> /dev/null | head -n -1 2> /dev/null`
  # replace the info in the output with a hint towards thorough mode
  systemdtimers="$systemdtimers\n\n${_gray}Enable thorough tests to see inactive timers${_reset}"
fi
if [ "$systemdtimers" ]; then
  render_text "Systemd timers" "$systemdtimers" "info"
fi

}

networking_info()
{
echo -e "${_yellow}### NETWORKING  ##########################################${_reset}" 

#nic information
nicinfo=`/sbin/ifconfig -a 2> /dev/null`
if [ "$nicinfo" ]; then
  render_text "Network and IP info" "$nicinfo" "info"
else
  #nic information (using ip)
  nicinfoip=`/sbin/ip a 2> /dev/null`
  if [ "$nicinfoip" ]; then
    render_text "Network and IP info" "$nicinfoip" "info"
  fi
fi

#arp information
arpinfo=`arp -a 2> /dev/null`
if [ "$arpinfo" ]; then
  render_text "ARP history" "$arpinfo" "info"
else
  #arp information (using ip)
  arpinfoip=`ip n 2> /dev/null`
  if [ "$arpinfoip" ]; then
    render_text "ARP history" "$arpinfoip" "info"
  fi
fi

#dns settings
nsinfo=`grep ${_color_flag} "nameserver" /etc/resolv.conf 2> /dev/null`
if [ "$nsinfo" ]; then
  render_text "Nameserver(s)" "$nsinfo" "info"
fi

nsinfosysd=`systemd-resolve --status 2> /dev/null`
if [ "$nsinfosysd" ]; then
  render_text "Nameserver(s)" "$nsinfosysd" "info"
fi

#default route configuration
defroute=`route 2> /dev/null | grep ${_color_flag} default`
if [ "$defroute" ]; then
  render_text "Default route" "$defroute" "info"
else
  #default route configuration (using ip)
  defrouteip=`ip r 2> /dev/null | grep ${_color_flag} default`
  if [ "$defrouteip" ]; then
    render_text "Default route" "$defrouteip" "info"
  fi
fi

#listening TCP
tcpservs=`netstat -lntp 2> /dev/null`
if [ "$tcpservs" ]; then
  render_text "Listening TCP" "$tcpservs" "info"
else
  #listening TCP (using ss)
  tcpservsip=`ss -lntp 2> /dev/null`
  if [ "$tcpservsip" ]; then
    render_text "Listening TCP" "$tcpservsip" "info"
  fi
fi

#listening UDP
udpservs=`netstat -lnup 2> /dev/null`
if [ "$udpservs" ]; then
  render_text "Listening UDP" "$udpservs" "info"
else
  #listening UDP (using ss)
  udpservsip=`ss -lnup 2> /dev/null`
  if [ ! "$udpservs" ] && [ "$udpservsip" ]; then
    render_text "Listening UDP" "$udpservsip" "info"
  fi
fi
}

services_info()
{
echo -e "${_yellow}### SERVICES #############################################${_reset}" 

#running processes
psaux=`ps aux 2> /dev/null`
if [ "$psaux" ]; then
  render_text "Running processes" "$psaux" "info"
fi

#lookup process binary path and permissisons
proclist=`ps -eo command | grep -v "^\(\[\|COMMAND\|(\)" | awk '{print $1}' | awk '!x[$0]++' 2> /dev/null`
if [ "$proclist" ]; then
  
  proclistbin=""
  for proc in $proclist; do
    procbin=`which -- $proc 2> /dev/null`
    # if which command failed, we skip this binary
    if [ -z "$procbin" ]; then continue; fi

    # we concatenate or init the list of processes
    if [ "$proclistbin" ]; then proclistbin="$proclistbin"$'\n'"$procbin"; else proclistbin="$procbin"; fi
  done

  # then we create the output list
  proclistoutput=""
  for procbin in $proclistbin; do
    entry=`ls ${_color_flag} -la $procbin 2> /dev/null`
    if [ "$proclistoutput" ]; then proclistoutput="$proclistoutput"$'\n'"$entry"; else proclistoutput="$entry"; fi
  done

  # and we print it
  if [ "$proclistoutput" ]; then
    render_text "Process binaries and associated permissions (from the above list)" "$proclistoutput" "info"
  fi
  
  if [ "$export" ]; then
    mkdir $format/ps-export/ 2>/dev/null
    for binary in $proclistbin; do cp --parents $binary $format/ps-export/; done 2> /dev/null
  fi
fi

#anything 'useful' in inetd.conf
inetdread=`grep -v '^#\|^$' /etc/inetd.conf 2> /dev/null`
if [ "$inetdread" ]; then
  render_text "Contents of /etc/inetd.conf (condensed)" "$inetdread" "info"

  if [ "$export" ]; then
    mkdir $format/etc-export/ 2>/dev/null
    cp /etc/inetd.conf $format/etc-export/inetd.conf 2>/dev/null
  fi
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`awk '{print $7}' /etc/inetd.conf 2> /dev/null | xargs -r ls -la 2> /dev/null`
if [ "$inetdbinperms" ]; then
  render_text "The related inetd binary permissions" "$inetdbinperms" "info"
fi

xinetdread=`cat /etc/xinetd.conf 2> /dev/null`
if [ "$xinetdread" ]; then
  render_text "Contents of /etc/xinetd.conf" "$xinetdread" "info"
  
  if [ "$export" ]; then
    mkdir $format/etc-export/ 2>/dev/null
    cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2> /dev/null
  fi
fi

xinetdincd=`grep ${_color_flag} "/etc/xinetd.d" /etc/xinetd.conf 2> /dev/null`
if [ "$xinetdincd" ]; then
  render_text "/etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below" "`ls -la /etc/xinetd.d 2> /dev/null`" "info"
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`awk '{print $7}' /etc/xinetd.conf 2> /dev/null | xargs -r ls -la 2> /dev/null`
if [ "$xinetdbinperms" ]; then
  render_text "The related xinetd binary permissions" "$xinetdbinperms" "info"
fi

initdread=`ls ${_color_flag} -la /etc/init.d 2> /dev/null`
if [ "$initdread" ]; then
  render_text "/etc/init.d/ binary permissions" "$initdread" "info"
fi

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2> /dev/null | xargs -r ls -la 2> /dev/null`
if [ "$initdperms" ]; then
  render_text "/etc/init.d/ files not belonging to root" "$initdperms" "info"
fi

rcdread=`ls ${_color_flag} -la /etc/rc.d/init.d 2>/dev/null`
if [ "$rcdread" ]; then
  render_text "/etc/rc.d/init.d binary permissions" "$rcdread" "info"
fi

#init.d files NOT belonging to root!
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2> /dev/null | xargs -r ls -la 2> /dev/null`
if [ "$rcdperms" ]; then
  render_text "/etc/rc.d/init.d files not belonging to root" "$rcdperms" "danger"
fi

usrrcdread=`ls ${_color_flag} -la /usr/local/etc/rc.d 2> /dev/null`
if [ "$usrrcdread" ]; then
  render_text "/usr/local/etc/rc.d binary permissions" "$usrrcdread" "info"
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2> /dev/null | xargs -r ls -la 2> /dev/null`
if [ "$usrrcdperms" ]; then
  render_text "/usr/local/etc/rc.d files not belonging to root" "$usrrcdperms" "danger"
fi

initread=`ls ${_color_flag} -la /etc/init/ 2>/dev/null`
if [ "$initread" ]; then
  render_text "/etc/init/ config file permissions" "$initread" "info"
fi

# upstart scripts not belonging to root
initperms=`find /etc/init \! -uid 0 -type f 2> /dev/null | xargs -r ls -la 2> /dev/null`
if [ "$initperms" ]; then
   render_text "/etc/init/ config files not belonging to root" "$initperms" "danger"
fi

if [ "$thorough" = "1" ]; then systemdread=`ls ${_color_flag} -lthR /lib/systemd/ /etc/systemd/ 2> /dev/null`;
else systemdread="`find /lib/systemd/ /etc/systemd/ -name *.service -type f -exec ls -la 2> /dev/null`"; fi
if [ "$systemdread" ]; then
  render_text "systemd config file permissions" "$systemdread" "info"
fi

# systemd files not belonging to root
systemdperms=`find /lib/systemd/ /etc/systemd/ \! -uid 0 -type f 2> /dev/null | xargs -r ls -la 2> /dev/null`
if [ "$systemdperms" ]; then
   render_text "systemd config files not belonging to root" "$systemdperms" "danger"
fi
}

software_configs()
{
echo -e "${_yellow}### SOFTWARE #############################################${_reset}" 

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`sudo -V 2> /dev/null | grep "Sudo version" | cut -d" " -f3`
if [ "$sudover" ]; then
  render_text "Sudo version" "$sudover" "info"
fi

#mysql details - if installed
mysqlver=`mysql --version 2> /dev/null`
if [ "$mysqlver" ]; then
  render_text "MYSQL version" "$mysqlver" "info"
fi

#checks to see if root/root will get us a connection
mysqlconnect=`mysqladmin -uroot -proot version 2> /dev/null`
if [ "$mysqlconnect" ]; then
  render_text "We can connect to the local MYSQL service with default root/root credentials" "$mysqlconnect" "danger"
fi

#mysql version details
mysqlconnectnopass=`mysqladmin -uroot version 2> /dev/null`
if [ "$mysqlconnectnopass" ]; then
  render_text "We can connect to the local MYSQL service as 'root' and without a password" "$mysqlconnectnopass" "danger"
fi

#postgres details - if installed
postgver=`psql -V 2> /dev/null`
if [ "$postgver" ]; then
  render_text "Postgres version" "$postgver" "info"
fi

#checks to see if any postgres password exists and connects to DB 'template'
psql_default_users="postgres pgsql"
for u in $psql_default_users; do
  for i in {0..9}; do
    w="template$i"
    postcon=`psql -U $u -w $w -c 'select version()' 2> /dev/null | grep ${_color_flag} version`

    if [ "$postcon" ]; then
      render_text "We can connect to Postgres DB $w as user $u with no password" "$postcon" "danger"
    fi
    
  done
done

#apache details - if installed
apachever=`apache2 -v 2> /dev/null; httpd -v 2> /dev/null`
if [ "$apachever" ]; then
  render_text "Apache version" "$apachever" "info"
  echo -e "\n"
fi

#what account is apache running under
apacheusr=`grep -i 'user\|group' /etc/apache2/envvars 2> /dev/null | awk '{sub(/.*\export /,"")}1' 2> /dev/null`
if [ "$apacheusr" ]; then
  render_text "Apache user configuration:${_reset}" "$apacheusr" "info"

  if [ "$export" ]; then
    mkdir --parents $format/etc-export/apache2/ 2> /dev/null
    cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2> /dev/null
  fi
fi

#installed apache modules
apachemodules=`apache2ctl -M 2> /dev/null; httpd -M 2> /dev/null`
if [ "$apachemodules" ]; then
  render_text "Installed Apache modules" "$apachemodules" "info"
fi

#htpasswd check
htpasswd=`find / -name .htpasswd -print -exec cat {} \; 2>/dev/null`
if [ "$htpasswd" ]; then
    render_text ".htpasswd found - could contain passwords" "$htpasswd" "danger"
fi

#anything in the default http home dirs (a thorough only check as output can be large)
if [ "$thorough" = "1" ]; then
  apache_dirs="/var/www/ /srv/www/htdocs/ /usr/local/www/apache2/data/ /opt/lampp/htdocs/"
  apachehomedirs=""
  for d in $apache_dirs; do
    entry=`ls -alhR $d 2> /dev/null`
    if [ "$apachehomedirs" ]; then apachehomedirs="$apachehomedirs"$'\n'"$entry"; else apachehomedirs="$entry"; fi
  done
  
  if [ "$apachehomedirs" ]; then
    render_text "Apache2 home dir contents" "$apachehomedirs" "info"
  fi
fi

}

interesting_files()
{
echo -e "${_yellow}### INTERESTING FILES ####################################${_reset}" 

#checks to see if various files are installed
bin_of_interest="nc netcat socat wget nmap gcc curl"
bin_of_interest_details=""
for bin_name in $bin_of_interest; do
  bin_fullpath=`which -- $bin_name 2> /dev/null`
  
  # if which command does not fail, we add the path
  if [ "$bin_fullpath" ]; then
    # we concatenate or init the details list
    if [ "$bin_of_interest_details" ]; then bin_of_interest_details="$bin_of_interest_details"$'\n'"$bin_fullpath"
    else bin_of_interest_details="$bin_fullpath"; fi  
  fi
done

if [ "$bin_of_interest_details" ]; then
  render_text "Useful file locations" "$bin_of_interest_details" "info"
fi

#limited search for installed compilers
compiler=`dpkg --list 2>/dev/null | grep compiler | grep -v decompiler 2> /dev/null && yum list installed 'gcc*' 2> /dev/null| grep gcc 2> /dev/null`
if [ "$compiler" ]; then
  render_text "Installed compilers" "$compiler" "info"
  echo -e "\n"
fi

#manual check - lists out sensitive files, can we read/modify etc.
sensitive_files="/etc/passwd /etc/group /etc/profile /etc/shadow /etc/master.passwd"
render_text "Can we read/write sensitive files" "`ls ${_color_flag} -la $sensitive_files 2> /dev/null`" "warning"

#search for suid files
allsuid=`find / -perm -4000 -type f 2> /dev/null`
if [ "$allsuid" ]; then
  suidfile_details=""
  for suidfile in $allsuid; do
    entry=`ls ${_color_flag} -la $suidfile 2> /dev/null`
    if [ "$entry" ]; then
      if [ "$suidfile_details" ]; then suidfile_details="$suidfile_details"$'\n'"$entry";
      else suidfile_details="$entry"; fi
    fi
  done
  
  if [ "$suidfile_details" ]; then
    render_text "SUID files" "$suidfile_details" "info"
  fi
  
  #list of 'interesting' suid files - feel free to make additions
  intsuid=`find $allsuid -perm -4000 -type f -exec ls -la {} \; 2> /dev/null | grep -w $binarylist 2> /dev/null`
  if [ "$intsuid" ]; then
    render_text "Possibly interesting SUID files" "$intsuid" "warning"
  fi

  #lists world-writable suid files
  wwsuid=`find $allsuid -perm -4002 -type f -exec ls -la {} 2> /dev/null \;`
  if [ "$wwsuid" ]; then
    render_text "World-writable SUID files" "$wwsuid" "warning"
  fi

  #lists world-writable suid files owned by root
  wwsuidrt=`find $allsuid -uid 0 -perm -4002 -type f -exec ls -la {} 2> /dev/null \;`
  if [ "$wwsuidrt" ]; then
    render_text "World-writable SUID files owned by root" "$wwsuidrt" "warning"
  fi
  
  if [ "$export" ]; then
    mkdir $format/suid-files/ 2> /dev/null
    for f in $allsuid; do cp $f $format/suid-files/; done 2> /dev/null
  fi
  
fi

#search for sgid files
allsgid=`find / -perm -2000 -type f 2> /dev/null`
if [ "$allsgid" ]; then
  sgid_details=""
  for sgidfile in $allsgid; do
    entry=`ls ${_color_flag} -la $sgidfile 2> /dev/null`
    if [ "$entry" ]; then
      if [ "$sgidfile_details" ]; then sgidfile_details="$sgidfile_details"$'\n'"$entry"
      else sgidfile_details="$entry"; fi
    fi
  done
  
  if [ "$sgidfile_details" ]; then
    render_text "SGID files" "$sgidfile_details" "info"
  fi
  
  #list of 'interesting' sgid files
  intsgid=`find $allsgid -perm -2000 -type f -exec ls -la {} \; 2> /dev/null | grep -w $binarylist 2> /dev/null`
  if [ "$intsgid" ]; then
    render_text "Possibly interesting SGID files" "$intsgid" "warning"
  fi

  #lists world-writable sgid files
  wwsgid=`find $allsgid -perm -2002 -type f -exec ls -la {} 2>/dev/null \;`
  if [ "$wwsgid" ]; then
    render_text "World-writable SGID files" "$wwsgid" "warning"
    echo -e "\n"
  fi

  #lists world-writable sgid files owned by root
  wwsgidrt=`find $allsgid -uid 0 -perm -2002 -type f -exec ls -la {} 2>/dev/null \;`
  if [ "$wwsgidrt" ]; then
    render_text "World-writable SGID files owned by root" "$wwsgidrt" "warning"
  fi
  
  if [ "$export" ]; then
    mkdir $format/sgid-files/ 2> /dev/null
    for i in $allsgid; do cp $i $format/sgid-files/; done 2> /dev/null
  fi
fi

#list all files with POSIX capabilities set along with there capabilities
fileswithcaps=`getcap -r / 2> /dev/null || /sbin/getcap -r / 2> /dev/null`
if [ "$fileswithcaps" ]; then
  render_text "Files with POSIX capabilities set" "$fileswithcaps" "info"
  
  if [ "$export" ]; then
    mkdir $format/files_with_capabilities/ 2> /dev/null
    for i in $fileswithcaps; do cp $i $format/files_with_capabilities/; done 2> /dev/null
  fi
fi

#searches /etc/security/capability.conf for users associated capapilies
userswithcaps=`grep -v '^#\|none\|^$' /etc/security/capability.conf 2> /dev/null`
if [ "$userswithcaps" ]; then
  render_text "Users with specific POSIX capabilities" "$userswithcaps" "info"

  #matches the capabilities found associated with users with the current user
  matchedcaps=`echo -e "$userswithcaps" | grep \`whoami\` | awk '{print $1}' 2> /dev/null`
  if [ "$matchedcaps" ]; then
    render_text "Capabilities associated with the current user" "$matchedcaps" "info"

    #matches the files with capapbilities with capabilities associated with the current user
    matchedfiles=`echo -e "$matchedcaps" | while read -r cap; do echo -e "$fileswithcaps" | grep "$cap"; done 2> /dev/null`
    if [ "$matchedfiles" ]; then
      render_text "Files with the same capabilities associated with the current user (You may want to try abusing those capabilties)" "$matchedfiles" "warning"
      
      #lists the permissions of the files having the same capabilies associated with the current user
      matchedfilesperms=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do ls -la $f; done 2> /dev/null`
      render_text "Permissions of files with the same capabilities associated with the current user" "$matchedfilesperms" "info"
      
      if [ "$matchedfilesperms" ]; then
        #checks if any of the files with same capabilities associated with the current user is writable
        writablematchedfiles=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do find $f -writable -exec ls -la {} \; 2>/dev/null; done`
        if [ "$writablematchedfiles" ]; then
          render_text "User/Group writable files with the same capabilities associated with the current user" "$writablematchedfiles" "info"
        fi
      fi
    fi
  fi
fi

if [ "$thorough" = "1" ]; then

  #look for private keys - thanks djhohnstein
  privatekeyfiles=`grep ${_color_flag} -rl "PRIVATE KEY-----" /home 2> /dev/null`
  if [ "$privatekeyfiles" ]; then
    render_text "Private SSH keys found" "$privatekeyfiles" "danger"
  fi

  #look for AWS keys - thanks djhohnstein
  awskeyfiles=`grep ${_color_flag} -rli "aws_secret_access_key" /home 2> /dev/null`
  if [ "$awskeyfiles" ]; then
    render_text "AWS secret keys found" "$awskeyfiles" "danger"
  fi

  #look for git credential files - thanks djhohnstein
  gitcredfiles=`find / -name ".git-credentials" 2> /dev/null`
  if [ "$gitcredfiles" ]; then
    render_text "Git credentials saved on the machine" "$gitcredfiles" "danger"
  fi

  #list all world-writable files excluding /proc and /sys
  wwfiles=`find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} 2> /dev/null \;`
  if [ "$wwfiles" ]; then
    render_text "World-writable files (excluding /proc and /sys)" "$wwfiles" "info"

    if [ "$export" ] && [ "$wwfiles" ]; then
      mkdir $format/ww-files/ 2> /dev/null
      for f in $wwfiles; do cp --parents $f $format/ww-files/; done 2> /dev/null
	fi
  fi

fi

#are any .plan files accessible in /home (could contain useful information)
usrplan=`find /home /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2> /dev/null \;`
if [ "$usrplan" ]; then
  render_text "Plan file permissions and contents" "$usrplan" "warning"

  if [ "$export" ]; then
    mkdir $format/plan_files/ 2> /dev/null
    for f in $usrplan; do cp --parents $f $format/plan_files/; done 2> /dev/null
  fi
fi

#are there any .rhosts files accessible - these may allow us to login as another user etc.
rhostsusr=`find /home /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostsusr" ]; then
  render_text "rhost config file(s) and file contents" "$rhostsusr" "warning"

  if [ "$export" ]; then
    mkdir $format/rhosts/ 2> /dev/null
    for i in $rhostsusr; do cp --parents $i $format/rhosts/; done 2> /dev/null
  fi
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2> /dev/null \; -exec cat {} 2> /dev/null \;`
if [ "$rhostssys" ]; then
  render_text "hosts.equiv file and contents" "$rhostssys" "info"

  if [ "$export" ]; then
    mkdir $format/rhosts/ 2> /dev/null
    for f in $rhostssys; do cp --parents $f $format/rhosts/; done 2> /dev/null
  fi
fi

#list nfs shares/permisisons etc.
nfsexports=`ls ${_color_flag} -la /etc/exports 2> /dev/null; cat /etc/exports 2> /dev/null`
if [ "$nfsexports" ]; then
  render_text "NFS config details" "$nfsexports" "warning"

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
    render_text "NFS displaying partitions and filesystems - you need to look for exotic filesystems" "$fstab" "info"
  fi
fi

#looking for credentials in /etc/fstab
fstab=`grep username /etc/fstab 2> /dev/null | awk '{sub(/.*\username=/,""); sub(/\,.*/,"")}1' 2> /dev/null | xargs -r echo username: 2> /dev/null; grep password /etc/fstab 2>/dev/null |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; grep domain /etc/fstab 2>/dev/null |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null`
if [ "$fstab" ]; then
  render_text "Looks like there are credentials in /etc/fstab" "$fstab" "danger"

  if [ "$export" ]; then
    mkdir $format/etc-exports/ 2> /dev/null
    cp /etc/fstab $format/etc-exports/fstab done 2> /dev/null
  fi
fi

fstabcred=`grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null`
if [ "$fstabcred" ]; then
  render_text "/etc/fstab contains a credentials file" "$fstabcred" "danger"
  
  if [ "$export" ] && [ "$fstabcred" ]; then
    mkdir $format/etc-exports/ 2> /dev/null
    cp /etc/fstab $format/etc-exports/fstab done 2> /dev/null
  fi
fi

if [ "$keyword" ]; then
  #use supplied keyword and cat *.conf files for potential matches - output will show line number within relevant file path where a match has been located
  confkey=`find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} \; 2> /dev/null`
  if [ "$confkey" ]; then
    render_text "Find keyword ($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears)" "$confkey" "warning"

    if [ "$export" ]; then
      confkeyfile=`find / -maxdepth 4 -name *.conf -type f -exec grep -lHn $keyword {} \; 2> /dev/null`
      mkdir --parents $format/keyword_file_matches/config_files/ 2> /dev/null
      for i in $confkeyfile; do cp --parents $i $format/keyword_file_matches/config_files/; done 2> /dev/null
    fi
  else 
    render_text "Find keyword ($keyword) in .conf files (recursive 4 levels)" "'$keyword' not found in any .conf files" "info"
  fi
  
  #use supplied keyword and cat *.php files for potential matches - output will show line number within relevant file path where a match has been located
  phpkey=`find / -maxdepth 10 -name *.php -type f -exec grep -Hn $keyword {} \; 2> /dev/null`
  if [ "$phpkey" ]; then
    render_text "Find keyword ($keyword) in .php files (recursive 10 levels - output format filepath:identified line number where keyword appears)" "$phpkey" "warning"
    
    if [ "$export" ]; then
      phpkeyfile=`find / -maxdepth 10 -name *.php -type f -exec grep -lHn $keyword {} \; 2> /dev/null`
      mkdir --parents $format/keyword_file_matches/php_files/ 2> /dev/null
      for i in $phpkeyfile; do cp --parents $i $format/keyword_file_matches/php_files/ ; done 2> /dev/null
    fi
    
  else
    render_text "Find keyword ($keyword) in .php files (recursive 10 levels)" "'$keyword' not found in any .php files" "info"
  fi

  #use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
  logkey=`find / -maxdepth 4 -name *.log -type f -exec grep -Hn $keyword {} \; 2> /dev/null`
  if [ "$logkey" ]; then
    render_text "Find keyword ($keyword) in .log files (recursive 4 levels - output format filepath:identified line number where keyword appears)" "$logkey" "warning"

    if [ "$export" ]; then
      logkeyfile=`find / -maxdepth 4 -name *.log -type f -exec grep -lHn $keyword {} \; 2> /dev/null`
	  mkdir --parents $format/keyword_file_matches/log_files/ 2> /dev/null
      for i in $logkeyfile; do cp --parents $i $format/keyword_file_matches/log_files/ ; done 2> /dev/null
    fi
  else 
	render_text "Find keyword ($keyword) in .log files (recursive 4 levels)" "'$keyword' not found in any .log files" "info"
  fi

  #use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
  inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2> /dev/null`
  if [ "$inikey" ]; then
    render_text "Find keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears)" "$inikey" "warning"

    if [ "$export" ] && [ "$inikey" ]; then
	  inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -lHn $keyword {} \; 2> /dev/null`
      mkdir --parents $format/keyword_file_matches/ini_files/ 2> /dev/null
      for i in $inikey; do cp --parents $i $format/keyword_file_matches/ini_files/ ; done 2> /dev/null
    fi
  else 
    render_text "Find keyword ($keyword) in .ini files (recursive 4 levels)" "'$keyword' not found in any .ini files" "info"
  fi

fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null`
if [ "$allconf" ]; then
  render_text "All *.conf files in /etc (recursive 1 level)" "$allconf" "info"

  if [ "$export" ]; then
    mkdir $format/conf-files/ 2> /dev/null
    for i in $allconf; do cp --parents $i $format/conf-files/; done 2> /dev/null
  fi
fi

# retrieves accessible history file paths (e.g. ~/.bash_history, ~/.wget-hsts, ~/.lesshst, ecc.)
# from users with valid home directories and shells
for entry in $(grep "^.*sh$" /etc/passwd 2> /dev/null); do
  user=`echo $entry | cut -d":" -f1`
  home=`echo $entry | cut -d":" -f6`
  usrhist=`ls ${_color_flag} -la $home/.*_history $home/.*-hsts $home/.*hst 2>/dev/null`
    
  if [ "$usrhist" ]; then
    render_text "${user}'s history files" "$usrhist" "warning"

    # if requested we export history files
    if [ "$export" ]; then
      # create dir only if it does not exist
        mkdir -p $format/history_files/ 2> /dev/null
        for f in $usrhist; do cp --parents $f $format/history_files/; done 2> /dev/null
    fi
  fi
done

#all accessible .bash_history files in /home
checkbashhist=`find /home -name .bash_history -print -exec cat {} 2> /dev/null \;`
if [ "$checkbashhist" ]; then
  render_text "Location and contents (if accessible) of .bash_history file(s)" "$checkbashhist" "info"
fi

#any .bak files that may be of interest
bakfiles="`find / -name *.bak -type f -exec ls -la {} 2> /dev/null \;`"
if [ "$bakfiles" ]; then
  render_text "Location and Permissions (if accessible) of .bak file(s)" "$bakfiles" "info"
fi

#is there any mail accessible
readmail=`ls ${_color_flag} -la /var/mail 2> /dev/null`
if [ "$readmail" ]; then
  render_text "Any interesting mail in /var/mail" "$readmail" "info"
fi

#can we read roots mail
readmailroot=`head /var/mail/root 2> /dev/null`
if [ "$readmailroot" ]; then
  render_text "We can read /var/mail/root! (snippet below)" "$readmailroot" "danger"
  
  if [ "$export" ]; then
    mkdir $format/mail-from-root/ 2> /dev/null
    cp $readmailroot $format/mail-from-root/ 2> /dev/null
  fi
fi
}

docker_checks()
{

#specific checks - check to see if we're in a docker container
dockercontainer=`grep ${_color_flag} -i docker /proc/self/cgroup 2> /dev/null; find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null`
if [ "$dockercontainer" ]; then
  render_text "It looks like we're in a Docker container" "$dockercontainer" "warning"
fi

#specific checks - check to see if we're a docker host
dockerhost=`docker --version 2> /dev/null; docker ps -a 2> /dev/null`
if [ "$dockerhost" ]; then
  render_text "It looks like we're hosting Docker" "$dockerhost" "info"
fi

#specific checks - are we a member of the docker group
dockergrp=`id | grep ${_color_flag} -i docker 2> /dev/null`
if [ "$dockergrp" ]; then
  render_text "We're a member of the (docker) group - could possibly misuse these rights!" "$dockergrp" "warning"
fi

#specific checks - are there any docker files present
dockerfiles=`find / -name Dockerfile -exec ls -l {} 2> /dev/null \;`
if [ "$dockerfiles" ]; then
  render_text "Anything juicy in the Dockerfile" "$dockerfiles" "warning"
fi

#specific checks - are there any docker files present
dockeryml=`find / -name docker-compose.yml -exec ls -l {} 2> /dev/null \;`
if [ "$dockeryml" ]; then
  render_text "Anything juicy in docker-compose.yml" "$dockeryml" "warning"
fi
}

lxc_container_checks()
{

#specific checks - are we in an lxd/lxc container
lxccontainer=`grep ${_color_flag} -qa container=lxc /proc/1/environ 2> /dev/null`
if [ "$lxccontainer" ]; then
  render_text "It looks like we're in a lxc container" "$lxccontainer" "info"
fi

#specific checks - are we a member of the lxd group
lxdgroup=`id | grep ${_color_flag} -i "(lxd)" 2> /dev/null`
if [ "$lxdgroup" ]; then
  render_text "We're a member of the (lxd) group - could possibly misuse these rights!" "$lxdgroup" "warning"
fi
}

footer()
{
echo -e "${_yellow}### SCAN COMPLETE ####################################${_reset}" 
}

call_each()
{
  header
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

while getopts "k:r:e:stCh" option; do
  case "${option}" in
    k) keyword=${OPTARG};;
    r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
    e) export=${OPTARG};;
    s) sudopass=1;;
    t) thorough=1;;
    C) _reset=""; _red=""; _yellow=""; _purple=""; _color_flag="";;
    h) usage; exit;;
    *) usage; exit;;
  esac
done

call_each | tee -a $report 2> /dev/null
#EndOfScript
