#!/bin/bash
#A script to enumerate local information from a Linux host
version="version 0.982"
#@rebootuser

# colored output vars
_reset="\e[00m"
_red="\e[00;31m"
_yellow="\e[00;33m"
_purple="\e[00;35m"
_gray="\e[0;37m"
_color_flag="--color"

#help function
usage () 
{ 
echo -e "\n${_red}#########################################################${_reset}" 
echo -e "${_red}#${_reset}" "${_yellow}Local Linux Enumeration & Privilege Escalation Script${_reset}" "${_red}#${_reset}"
echo -e "${_red}#########################################################${_reset}"
echo -e "${_yellow}# www.rebootuser.com | @rebootuser ${_reset}"
echo -e "${_yellow}# $version${_reset}\n"
echo -e "${_yellow}# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t ${_reset}\n"

		echo "OPTIONS:"
		echo "-k	Enter keyword"
		echo "-e	Enter export location"
		echo "-s 	Supply user password for sudo checks (INSECURE)"
		echo "-t	Include thorough (lengthy) tests"
		echo "-r	Enter report name" 
        echo "-C	Disable colored output"
		echo "-h	Displays this help text"
		echo -e "\n"
		echo "Running with no options = limited scans/no output file"
		
echo -e "${_red}#########################################################${_reset}"		
}
header()
{
echo -e "\n${_red}#########################################################${_reset}" 
echo -e "${_red}#${_reset}" "${_yellow}Local Linux Enumeration & Privilege Escalation Script${_reset}" "${_red}#${_reset}" 
echo -e "${_red}#########################################################${_reset}" 
echo -e "${_yellow}# www.rebootuser.com${_reset}" 
echo -e "${_yellow}# $version${_reset}\n" 

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
unameinfo=`uname -a 2>/dev/null`
if [ "$unameinfo" ]; then
  echo -e "${_red}[-] Kernel information:${_reset}\n$unameinfo" 
  echo -e "\n" 
fi

procver=`cat /proc/version 2>/dev/null`
if [ "$procver" ]; then
  echo -e "${_red}[-] Kernel information (continued):${_reset}\n$procver" 
  echo -e "\n" 
fi

#search all *-release files for version info
release=`cat /etc/*-release 2>/dev/null`
if [ "$release" ]; then
  echo -e "${_red}[-] Specific release information:${_reset}\n$release" 
  echo -e "\n" 
fi

#target hostname info
hostnamed=`hostname 2>/dev/null`
if [ "$hostnamed" ]; then
  echo -e "${_red}[-] Hostname:${_reset}\n$hostnamed" 
  echo -e "\n" 
fi
}

user_info()
{
echo -e "${_yellow}### USER/GROUP ##########################################${_reset}" 

#current user details
currusr=`id 2>/dev/null`
if [ "$currusr" ]; then
  echo -e "${_red}[-] Current user/group info:${_reset}\n$currusr" 
  echo -e "\n"
fi

#last logged on user information
lastlogedonusrs=`lastlog 2>/dev/null |grep -v "Never" 2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  echo -e "${_red}[-] Users that have previously logged onto the system:${_reset}\n$lastlogedonusrs" 
  echo -e "\n" 
fi

#who else is logged on
loggedonusrs=`w 2>/dev/null`
if [ "$loggedonusrs" ]; then
  echo -e "${_red}[-] Who else is logged on:${_reset}\n$loggedonusrs" 
  echo -e "\n"
fi

# save all users in the users variable
users=`grep -v '^#' /etc/passwd 2> /dev/null | cut -d":" -f1 2> /dev/null`

#lists all id's and respective group(s)
grpinfo=`for u in $users; do echo -e "${_purple}$u${_reset}:\n\t$(id $u)"; done 2>/dev/null`
if [ "$grpinfo" ]; then
  echo -e "${_red}[-] Group memberships:${_reset}\n$grpinfo"
  echo -e "\n"
fi

#added by phackt - look for adm group (thanks patrick)
adm_users=$(echo -e "$grpinfo" | grep "(adm)")
if [[ ! -z $adm_users ]];
  then
    echo -e "${_red}[-] It looks like we have some admin users:${_reset}\n$adm_users"
    echo -e "\n"
fi

#checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  echo -e "${_yellow}[+] It looks like we have password hashes in /etc/passwd!${_reset}\n$hashesinpasswd" 
  echo -e "\n"
fi

#contents of /etc/passwd
readpasswd=`cat /etc/passwd 2>/dev/null`
if [ "$readpasswd" ]; then
  echo -e "${_red}[-] Contents of /etc/passwd:${_reset}\n$readpasswd" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/passwd $format/etc-export/passwd 2>/dev/null
fi

#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$readshadow" ]; then
  echo -e "${_yellow}[+] We can read the shadow file!${_reset}\n$readshadow" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readshadow" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/shadow $format/etc-export/shadow 2>/dev/null
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  echo -e "${_yellow}[+] We can read the master.passwd file!${_reset}\n$readmasterpasswd" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readmasterpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/master.passwd $format/etc-export/master.passwd 2>/dev/null
fi

#all root accounts (uid 0)
superman=`grep -v '^#' /etc/passwd 2> /dev/null | awk -F':' '$3 == 0 {print $1}' 2> /dev/null`
if [ "$superman" ]; then
  echo -e "${_red}[-] Super user account(s):${_reset}\n$superman"
  echo -e "\n"
fi

# we proceed with sudo checks, only if we can get the sudo binary path
sudobin=`which sudo`
if [ "$sudobin" ]; then

  #pull out vital sudoers info
  sudoers=`grep -v '^#' /etc/sudoers 2> /dev/null | grep -v '^$' 2> /dev/null`
  if [ "$sudoers" ]; then
    echo -e "${_red}[-] Sudoers configuration (condensed):${_reset}$sudoers\n"

    if [ "$export" ]; then
      mkdir $format/etc-export/ 2> /dev/null
      cp /etc/sudoers $format/etc-export/sudoers 2> /dev/null
    fi
  fi

  #can we sudo without supplying a password?
  sudoperms=`echo '' | sudo -S -l -k 2> /dev/null`
  if [ "$sudoperms" ]; then
    echo -e "${_yellow}[+] We can sudo without supplying a password!${_reset}\n$sudoperms\n"

    #known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values)
    sudopwnage=`echo "$sudoperms" | xargs -n 1 2> /dev/null | sed 's/,*$//g' 2> /dev/null | grep -w $binarylist 2> /dev/null`
    if [ "$sudopwnage" ]; then
      echo -e "${_yellow}[+] Possible sudo pwnage!${_reset}\n$sudopwnage\n"
    fi

  else
    
    if [ "$sudopass" ]; then
      #can we sudo when supplying a password?
      sudoauth=`echo $userpassword | sudo -S -l -k 2> /dev/null`
      if [ "$sudoauth" ]; then
        echo -e "${_yellow}[+] We can sudo when supplying a password!${_reset}\n$sudoauth\n"

        #known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values) - authenticated
        sudopermscheck=`echo "$sudoauth" | xargs -n 1 2> /dev/null | sed 's/,*$//g' 2> /dev/null | grep -w $binarylist 2> /dev/null`
        if [ "$sudopermscheck" ]; then
          echo -e "${_yellow}[-] Possible sudo pwnage!${_reset}\n$sudopermscheck\n"
        fi

      fi
      
    fi
  fi

  #who has sudoed in the past
  sudoerhomelist=`find /home -name .sudo_as_admin_successful -exec dirname {} \; 2> /dev/null | sort -u`
  if [ "$sudoerhomelist" ]; then
    echo -e "${_red}[-] Users that have recently used ${_yellow}sudo${_red}:${_reset}\n"
    for h in $sudoerhomelist; do
      ls -dl "$h" 2> /dev/null | awk 'NR==1 {print $3}' 2> /dev/null
    done
    echo -e "\n"
  fi

fi

#checks to see if roots home directory is accessible
rthmdir=`ls ${_color_flag} -ahl /root/ 2>/dev/null`
if [ "$rthmdir" ]; then
  echo -e "${_yellow}[+] We can read root's home directory!${_reset}\n$rthmdir" 
  echo -e "\n"
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls ${_color_flag} -ahl /home/ 2>/dev/null`
if [ "$homedirperms" ]; then
  echo -e "${_red}[-] Are permissions on /home directories lax:${_reset}\n$homedirperms" 
  echo -e "\n"
fi

#is root permitted to login via ssh
sshrootlogin=`grep '^\s*PermitRootLogin\s\+' /etc/ssh/sshd_config 2> /dev/null | cut -d' ' -f2`
if [ "$sshrootlogin" = "yes" ]; then
  echo -e "${_red}[-] Root is allowed to login via SSH: ${_reset}${sshrootlogin}${_red}!${_reset}\n"
fi

#thorough checks
if [ "$thorough" = "1" ]; then

  #looks for files we can write to that don't belong to us
  grfilesall=`find / -writable ! -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$grfilesall" ]; then
    echo -e "${_red}[-] Files not owned by user but writable by group:${_reset}\n$grfilesall" 
    echo -e "\n"
  fi

  #looks for files that belong to us
  ourfilesall=`find / -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$ourfilesall" ]; then
    echo -e "${_red}[-] Files owned by our user:${_reset}\n$ourfilesall"
    echo -e "\n"
  fi

  #looks for hidden files
  hiddenfiles=`find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$hiddenfiles" ]; then
    echo -e "${_red}[-] Hidden files:${_reset}\n$hiddenfiles"
    echo -e "\n"
  fi
  
  #looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
  wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
  if [ "$wrfileshm" ]; then
    echo -e "${_red}[-] World-readable files within /home:${_reset}\n$wrfileshm\n"

    if [ "$export" ]; then
      mkdir $format/wr-files/ 2> /dev/null
      for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2> /dev/null
    fi
  fi

  #lists current user's home directory contents
  homedircontents=`ls ${_color_flag} -ahl ~ 2>/dev/null`
  if [ "$homedircontents" ] ; then
    echo -e "${_red}[-] Home directory contents:${_reset}\n$homedircontents\n"
  fi

  #checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
  sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \;`
  if [ "$sshfiles" ]; then
    echo -e "${_red}[-] SSH keys/host information found in the following locations:${_reset}\n$sshfiles\n"
    
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
envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null`
if [ "$envinfo" ]; then
  echo -e "${_red}[-] Environment information:${_reset}\n$envinfo" 
  echo -e "\n"
fi

#check if selinux is enabled
sestatus=`sestatus 2>/dev/null`
if [ "$sestatus" ]; then
  echo -e "${_red}[-] SELinux seems to be present:${_reset}\n$sestatus"
  echo -e "\n"
fi

#phackt

#current path configuration
pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
  pathswriteable=`ls -ld $(echo $PATH | tr ":" " ")`
  echo -e "${_red}[-] Path information:${_reset}\n$pathinfo" 
  echo -e "$pathswriteable"
  echo -e "\n"
fi

#lists available shells
shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$shellinfo" ]; then
  echo -e "${_red}[-] Available shells:${_reset}\n$shellinfo" 
  echo -e "\n"
fi

#current umask value with both octal and symbolic output
umaskvalue=`umask -S 2>/dev/null & umask 2>/dev/null`
if [ "$umaskvalue" ]; then
  echo -e "${_red}[-] Current umask value:${_reset}\n$umaskvalue" 
  echo -e "\n"
fi

#umask value as in /etc/login.defs
umaskdef=`grep ${_color_flag} -i "^UMASK" /etc/login.defs 2>/dev/null`
if [ "$umaskdef" ]; then
  echo -e "${_red}[-] umask value as specified in /etc/login.defs:${_reset}\n$umaskdef" 
  echo -e "\n"
fi

#password policy information as stored in /etc/login.defs
logindefs=`grep ${_color_flag} "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null`
if [ "$logindefs" ]; then
  echo -e "${_red}[-] Password and storage information:${_reset}\n$logindefs" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$logindefs" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
fi
}

job_info()
{
echo -e "${_yellow}### JOBS/TASKS ##########################################${_reset}" 

#are there any cron jobs configured
cronjobs=`ls ${_color_flag} -la /etc/cron* 2>/dev/null`
if [ "$cronjobs" ]; then
  echo -e "${_red}[-] Cron jobs:${_reset}\n$cronjobs" 
  echo -e "\n"
fi

#can we manipulate these jobs in any way
cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobwwperms" ]; then
  echo -e "${_yellow}[+] World-writable cron jobs and file contents:${_reset}\n$cronjobwwperms" 
  echo -e "\n"
fi

#contab contents
crontabvalue=`cat /etc/crontab 2>/dev/null`
if [ "$crontabvalue" ]; then
  echo -e "${_red}[-] Crontab contents:${_reset}\n$crontabvalue" 
  echo -e "\n"
fi

crontabvar=`ls ${_color_flag} -la /var/spool/cron/crontabs 2>/dev/null`
if [ "$crontabvar" ]; then
  echo -e "${_red}[-] Anything interesting in /var/spool/cron/crontabs:${_reset}\n$crontabvar" 
  echo -e "\n"
fi

anacronjobs=`ls ${_color_flag} -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
if [ "$anacronjobs" ]; then
  echo -e "${_red}[-] Anacron jobs and associated file permissions:${_reset}\n$anacronjobs" 
  echo -e "\n"
fi

anacrontab=`ls ${_color_flag} -la /var/spool/anacron 2>/dev/null`
if [ "$anacrontab" ]; then
  echo -e "${_red}[-] When were jobs last executed (/var/spool/anacron contents):${_reset}\n$anacrontab" 
  echo -e "\n"
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`echo $users | xargs -n1 crontab -l -u 2>/dev/null`
if [ "$cronother" ]; then
  echo -e "${_red}[-] Jobs held by all users:${_reset}\n$cronother" 
  echo -e "\n"
fi

# list systemd timers
if [ "$thorough" = "1" ]; then
  # include inactive timers in thorough mode
  systemdtimers="$(systemctl list-timers --all 2>/dev/null)"
  info=""
else
  systemdtimers="$(systemctl list-timers 2>/dev/null |head -n -1 2>/dev/null)"
  # replace the info in the output with a hint towards thorough mode
  info="${_gray}Enable thorough tests to see inactive timers${_reset}"
fi
if [ "$systemdtimers" ]; then
  echo -e "${_red}[-] Systemd timers:${_reset}\n$systemdtimers\n$info"
  echo -e "\n"
fi

}

networking_info()
{
echo -e "${_yellow}### NETWORKING  ##########################################${_reset}" 

#nic information
nicinfo=`/sbin/ifconfig -a 2>/dev/null`
if [ "$nicinfo" ]; then
  echo -e "${_red}[-] Network and IP info:${_reset}\n$nicinfo" 
  echo -e "\n"
fi

#nic information (using ip)
nicinfoip=`/sbin/ip a 2>/dev/null`
if [ ! "$nicinfo" ] && [ "$nicinfoip" ]; then
  echo -e "${_red}[-] Network and IP info:${_reset}\n$nicinfoip" 
  echo -e "\n"
fi

arpinfo=`arp -a 2>/dev/null`
if [ "$arpinfo" ]; then
  echo -e "${_red}[-] ARP history:${_reset}\n$arpinfo" 
  echo -e "\n"
fi

arpinfoip=`ip n 2>/dev/null`
if [ ! "$arpinfo" ] && [ "$arpinfoip" ]; then
  echo -e "${_red}[-] ARP history:${_reset}\n$arpinfoip" 
  echo -e "\n"
fi

#dns settings
nsinfo=`grep ${_color_flag} "nameserver" /etc/resolv.conf 2>/dev/null`
if [ "$nsinfo" ]; then
  echo -e "${_red}[-] Nameserver(s):${_reset}\n$nsinfo" 
  echo -e "\n"
fi

nsinfosysd=`systemd-resolve --status 2>/dev/null`
if [ "$nsinfosysd" ]; then
  echo -e "${_red}[-] Nameserver(s):${_reset}\n$nsinfosysd" 
  echo -e "\n"
fi

#default route configuration
defroute=`route 2>/dev/null | grep default`
if [ "$defroute" ]; then
  echo -e "${_red}[-] Default route:${_reset}\n$defroute" 
  echo -e "\n"
fi

#default route configuration
defrouteip=`ip r 2>/dev/null | grep default`
if [ ! "$defroute" ] && [ "$defrouteip" ]; then
  echo -e "${_red}[-] Default route:${_reset}\n$defrouteip" 
  echo -e "\n"
fi

#listening TCP
tcpservs=`netstat -ntpl 2>/dev/null`
if [ "$tcpservs" ]; then
  echo -e "${_red}[-] Listening TCP:${_reset}\n$tcpservs" 
  echo -e "\n"
fi

tcpservsip=`ss -t -l -n 2>/dev/null`
if [ ! "$tcpservs" ] && [ "$tcpservsip" ]; then
  echo -e "${_red}[-] Listening TCP:${_reset}\n$tcpservsip" 
  echo -e "\n"
fi

#listening UDP
udpservs=`netstat -nupl 2>/dev/null`
if [ "$udpservs" ]; then
  echo -e "${_red}[-] Listening UDP:${_reset}\n$udpservs" 
  echo -e "\n"
fi

udpservsip=`ss -u -l -n 2>/dev/null`
if [ ! "$udpservs" ] && [ "$udpservsip" ]; then
  echo -e "${_red}[-] Listening UDP:${_reset}\n$udpservsip" 
  echo -e "\n"
fi
}

services_info()
{
echo -e "${_yellow}### SERVICES #############################################${_reset}" 

#running processes
psaux=`ps aux 2>/dev/null`
if [ "$psaux" ]; then
  echo -e "${_red}[-] Running processes:${_reset}\n$psaux" 
  echo -e "\n"
fi

#lookup process binary path and permissisons
proclist=`ps -eo command | grep -v "^\(\[\|COMMAND\|(\)" | awk '{print $1}' | awk '!x[$0]++' 2> /dev/null`
if [ "$proclist" ]; then
  echo -e "${_red}[-] Process binaries and associated permissions (from above list):${_reset}\n"
  
  proclistbin=""
  for proc in $proclist; do
    procbin=`which -- $proc 2> /dev/null`
    # if which command failed, we skip this binary
    if [ -z "$procbin" ]; then continue; fi

    # we concatenate or init the list of processes
    if [ "$proclistbin" ]; then proclistbin="$proclistbin"$'\n'"$procbin"; else proclistbin="$procbin"; fi
  done

  # we then present the output 
  for procbin in $proclistbin; do
    ls ${_color_flag} -la $procbin 2> /dev/null
  done

  echo -e "\n"
  
  if [ "$export" ]; then
    mkdir $format/ps-export/ 2>/dev/null
    for binary in $proclistbin; do cp --parents $binary $format/ps-export/; done 2> /dev/null
  fi
fi

#anything 'useful' in inetd.conf
inetdread=`cat /etc/inetd.conf 2>/dev/null`
if [ "$inetdread" ]; then
  echo -e "${_red}[-] Contents of /etc/inetd.conf:${_reset}\n$inetdread" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$inetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/inetd.conf $format/etc-export/inetd.conf 2>/dev/null
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`awk '{print $7}' /etc/inetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$inetdbinperms" ]; then
  echo -e "${_red}[-] The related inetd binary permissions:${_reset}\n$inetdbinperms" 
  echo -e "\n"
fi

xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdread" ]; then
  echo -e "${_red}[-] Contents of /etc/xinetd.conf:${_reset}\n$xinetdread" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$xinetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2>/dev/null
fi

xinetdincd=`grep ${_color_flag} "/etc/xinetd.d" /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdincd" ]; then
  echo -e "${_red}[-] /etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:${_reset}"; ls -la /etc/xinetd.d 2>/dev/null 
  echo -e "\n"
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`awk '{print $7}' /etc/xinetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$xinetdbinperms" ]; then
  echo -e "${_red}[-] The related xinetd binary permissions:${_reset}\n$xinetdbinperms" 
  echo -e "\n"
fi

initdread=`ls ${_color_flag} -la /etc/init.d 2>/dev/null`
if [ "$initdread" ]; then
  echo -e "${_red}[-] /etc/init.d/ binary permissions:${_reset}\n$initdread" 
  echo -e "\n"
fi

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initdperms" ]; then
  echo -e "${_red}[-] /etc/init.d/ files not belonging to root:${_reset}\n$initdperms" 
  echo -e "\n"
fi

rcdread=`ls ${_color_flag} -la /etc/rc.d/init.d 2>/dev/null`
if [ "$rcdread" ]; then
  echo -e "${_red}[-] /etc/rc.d/init.d binary permissions:${_reset}\n$rcdread" 
  echo -e "\n"
fi

#init.d files NOT belonging to root!
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$rcdperms" ]; then
  echo -e "${_red}[-] /etc/rc.d/init.d files not belonging to root:${_reset}\n$rcdperms" 
  echo -e "\n"
fi

usrrcdread=`ls ${_color_flag} -la /usr/local/etc/rc.d 2>/dev/null`
if [ "$usrrcdread" ]; then
  echo -e "${_red}[-] /usr/local/etc/rc.d binary permissions:${_reset}\n$usrrcdread" 
  echo -e "\n"
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$usrrcdperms" ]; then
  echo -e "${_red}[-] /usr/local/etc/rc.d files not belonging to root:${_reset}\n$usrrcdperms" 
  echo -e "\n"
fi

initread=`ls ${_color_flag} -la /etc/init/ 2>/dev/null`
if [ "$initread" ]; then
  echo -e "${_red}[-] /etc/init/ config file permissions:${_reset}\n$initread"
  echo -e "\n"
fi

# upstart scripts not belonging to root
initperms=`find /etc/init \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initperms" ]; then
   echo -e "${_red}[-] /etc/init/ config files not belonging to root:${_reset}\n$initperms"
   echo -e "\n"
fi

systemdread=`ls ${_color_flag} -lthR /lib/systemd/ 2>/dev/null`
if [ "$systemdread" ]; then
  echo -e "${_red}[-] /lib/systemd/* config file permissions:${_reset}\n$systemdread"
  echo -e "\n"
fi

# systemd files not belonging to root
systemdperms=`find /lib/systemd/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$systemdperms" ]; then
   echo -e "${_yellow}[+] /lib/systemd/* config files not belonging to root:${_reset}\n$systemdperms"
   echo -e "\n"
fi
}

software_configs()
{
echo -e "${_yellow}### SOFTWARE #############################################${_reset}" 

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null`
if [ "$sudover" ]; then
  echo -e "${_red}[-] Sudo version:${_reset}\n$sudover" 
  echo -e "\n"
fi

#mysql details - if installed
mysqlver=`mysql --version 2>/dev/null`
if [ "$mysqlver" ]; then
  echo -e "${_red}[-] MYSQL version:${_reset}\n$mysqlver" 
  echo -e "\n"
fi

#checks to see if root/root will get us a connection
mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null`
if [ "$mysqlconnect" ]; then
  echo -e "${_yellow}[+] We can connect to the local MYSQL service with default root/root credentials!${_reset}\n$mysqlconnect" 
  echo -e "\n"
fi

#mysql version details
mysqlconnectnopass=`mysqladmin -uroot version 2>/dev/null`
if [ "$mysqlconnectnopass" ]; then
  echo -e "${_yellow}[+] We can connect to the local MYSQL service as 'root' and without a password!${_reset}\n$mysqlconnectnopass" 
  echo -e "\n"
fi

#postgres details - if installed
postgver=`psql -V 2>/dev/null`
if [ "$postgver" ]; then
  echo -e "${_red}[-] Postgres version:${_reset}\n$postgver" 
  echo -e "\n"
fi

#checks to see if any postgres password exists and connects to DB 'template0' - following commands are a variant on this
postcon1=`psql -U postgres -w template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon1" ]; then
  echo -e "${_yellow}[+] We can connect to Postgres DB 'template0' as user 'postgres' with no password!:${_reset}\n$postcon1" 
  echo -e "\n"
fi

postcon11=`psql -U postgres -w template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon11" ]; then
  echo -e "${_yellow}[+] We can connect to Postgres DB 'template1' as user 'postgres' with no password!:${_reset}\n$postcon11" 
  echo -e "\n"
fi

postcon2=`psql -U pgsql -w template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon2" ]; then
  echo -e "${_yellow}[+] We can connect to Postgres DB 'template0' as user 'psql' with no password!:${_reset}\n$postcon2" 
  echo -e "\n"
fi

postcon22=`psql -U pgsql -w template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon22" ]; then
  echo -e "${_yellow}[+] We can connect to Postgres DB 'template1' as user 'psql' with no password!:${_reset}\n$postcon22" 
  echo -e "\n"
fi

#apache details - if installed
apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
if [ "$apachever" ]; then
  echo -e "${_red}[-] Apache version:${_reset}\n$apachever" 
  echo -e "\n"
fi

#what account is apache running under
apacheusr=`grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null`
if [ "$apacheusr" ]; then
  echo -e "${_red}[-] Apache user configuration:${_reset}\n$apacheusr" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$apacheusr" ]; then
  mkdir --parents $format/etc-export/apache2/ 2>/dev/null
  cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2>/dev/null
fi

#installed apache modules
apachemodules=`apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null`
if [ "$apachemodules" ]; then
  echo -e "${_red}[-] Installed Apache modules:${_reset}\n$apachemodules" 
  echo -e "\n"
fi

#htpasswd check
htpasswd=`find / -name .htpasswd -print -exec cat {} \; 2>/dev/null`
if [ "$htpasswd" ]; then
    echo -e "${_yellow}[-] htpasswd found - could contain passwords:${_reset}\n$htpasswd"
    echo -e "\n"
fi

#anything in the default http home dirs (a thorough only check as output can be large)
if [ "$thorough" = "1" ]; then
  apache_dirs="/var/www/ /srv/www/htdocs/ /usr/local/www/apache2/data/ /opt/lampp/htdocs/"
  apachehomedirs=""
  for d in $apache_dirs; do
    apachehomedirs="$apachehomedirs`ls -alhR $d 2>/dev/null`"
  done
  
  if [ "$apachehomedirs" ]; then
    echo -e "${_red}[-] www home dir contents:${_reset}\n$apachehomedirs\n"
  fi
fi

}

interesting_files()
{
echo -e "${_yellow}### INTERESTING FILES ####################################${_reset}" 

#checks to see if various files are installed
bin_of_interest="nc netcat socat wget nmap gcc curl"
echo -e "${_red}[-] Useful file locations:${_reset}"
for b in $bin_of_interest; do
  which $b 2> /dev/null
done
echo -e "\n"

#limited search for installed compilers
compiler=`dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null`
if [ "$compiler" ]; then
  echo -e "${_red}[-] Installed compilers:${_reset}\n$compiler" 
  echo -e "\n"
fi

#manual check - lists out sensitive files, can we read/modify etc.
echo -e "${_red}[-] Can we read/write sensitive files:${_reset}" ; ls -la /etc/passwd 2>/dev/null ; ls -la /etc/group 2>/dev/null ; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null ; ls -la /etc/master.passwd 2>/dev/null 
echo -e "\n" 

#search for suid files
allsuid=`find / -perm -4000 -type f 2>/dev/null`
findsuid=`find $allsuid -perm -4000 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$findsuid" ]; then
  echo -e "${_red}[-] SUID files:${_reset}\n$findsuid" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$findsuid" ]; then
  mkdir $format/suid-files/ 2>/dev/null
  for i in $findsuid; do cp $i $format/suid-files/; done 2>/dev/null
fi

#list of 'interesting' suid files - feel free to make additions
intsuid=`find $allsuid -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$intsuid" ]; then
  echo -e "${_yellow}[+] Possibly interesting SUID files:${_reset}\n$intsuid" 
  echo -e "\n"
fi

#lists world-writable suid files
wwsuid=`find $allsuid -perm -4002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsuid" ]; then
  echo -e "${_yellow}[+] World-writable SUID files:${_reset}\n$wwsuid" 
  echo -e "\n"
fi

#lists world-writable suid files owned by root
wwsuidrt=`find $allsuid -uid 0 -perm -4002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsuidrt" ]; then
  echo -e "${_yellow}[+] World-writable SUID files owned by root:${_reset}\n$wwsuidrt" 
  echo -e "\n"
fi

#search for sgid files
allsgid=`find / -perm -2000 -type f 2>/dev/null`
findsgid=`find $allsgid -perm -2000 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$findsgid" ]; then
  echo -e "${_red}[-] SGID files:${_reset}\n$findsgid" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$findsgid" ]; then
  mkdir $format/sgid-files/ 2>/dev/null
  for i in $findsgid; do cp $i $format/sgid-files/; done 2>/dev/null
fi

#list of 'interesting' sgid files
intsgid=`find $allsgid -perm -2000 -type f  -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$intsgid" ]; then
  echo -e "${_yellow}[+] Possibly interesting SGID files:${_reset}\n$intsgid" 
  echo -e "\n"
fi

#lists world-writable sgid files
wwsgid=`find $allsgid -perm -2002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsgid" ]; then
  echo -e "${_yellow}[+] World-writable SGID files:${_reset}\n$wwsgid" 
  echo -e "\n"
fi

#lists world-writable sgid files owned by root
wwsgidrt=`find $allsgid -uid 0 -perm -2002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsgidrt" ]; then
  echo -e "${_yellow}[+] World-writable SGID files owned by root:${_reset}\n$wwsgidrt" 
  echo -e "\n"
fi

#list all files with POSIX capabilities set along with there capabilities
fileswithcaps=`getcap -r / 2>/dev/null || /sbin/getcap -r / 2>/dev/null`
if [ "$fileswithcaps" ]; then
  echo -e "${_red}[+] Files with POSIX capabilities set:${_reset}\n$fileswithcaps"
  echo -e "\n"
fi

if [ "$export" ] && [ "$fileswithcaps" ]; then
  mkdir $format/files_with_capabilities/ 2>/dev/null
  for i in $fileswithcaps; do cp $i $format/files_with_capabilities/; done 2>/dev/null
fi

#searches /etc/security/capability.conf for users associated capapilies
userswithcaps=`grep -v '^#\|none\|^$' /etc/security/capability.conf 2>/dev/null`
if [ "$userswithcaps" ]; then
  echo -e "${_yellow}[+] Users with specific POSIX capabilities:${_reset}\n$userswithcaps"
  echo -e "\n"
fi

if [ "$userswithcaps" ] ; then
#matches the capabilities found associated with users with the current user
matchedcaps=`echo -e "$userswithcaps" | grep \`whoami\` | awk '{print $1}' 2>/dev/null`
	if [ "$matchedcaps" ]; then
		echo -e "${_yellow}[+] Capabilities associated with the current user:${_reset}\n$matchedcaps"
		echo -e "\n"
		#matches the files with capapbilities with capabilities associated with the current user
		matchedfiles=`echo -e "$matchedcaps" | while read -r cap ; do echo -e "$fileswithcaps" | grep "$cap" ; done 2>/dev/null`
		if [ "$matchedfiles" ]; then
			echo -e "${_yellow}[+] Files with the same capabilities associated with the current user (You may want to try abusing those capabilties):${_reset}\n$matchedfiles"
			echo -e "\n"
			#lists the permissions of the files having the same capabilies associated with the current user
			matchedfilesperms=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do ls -la $f ;done 2>/dev/null`
			echo -e "${_yellow}[+] Permissions of files with the same capabilities associated with the current user:${_reset}\n$matchedfilesperms"
			echo -e "\n"
			if [ "$matchedfilesperms" ]; then
				#checks if any of the files with same capabilities associated with the current user is writable
				writablematchedfiles=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do find $f -writable -exec ls -la {} + ;done 2>/dev/null`
				if [ "$writablematchedfiles" ]; then
					echo -e "${_yellow}[+] User/Group writable files with the same capabilities associated with the current user:${_reset}\n$writablematchedfiles"
					echo -e "\n"
				fi
			fi
		fi
	fi
fi

#look for private keys - thanks djhohnstein
if [ "$thorough" = "1" ]; then
privatekeyfiles=`grep ${_color_flag} -rl "PRIVATE KEY-----" /home 2>/dev/null`
	if [ "$privatekeyfiles" ]; then
  		echo -e "${_yellow}[+] Private SSH keys found!:${_reset}\n$privatekeyfiles"
  		echo -e "\n"
	fi
fi

#look for AWS keys - thanks djhohnstein
if [ "$thorough" = "1" ]; then
awskeyfiles=`grep ${_color_flag} -rli "aws_secret_access_key" /home 2>/dev/null`
	if [ "$awskeyfiles" ]; then
  		echo -e "${_yellow}[+] AWS secret keys found!:${_reset}\n$awskeyfiles"
  		echo -e "\n"
	fi
fi

#look for git credential files - thanks djhohnstein
if [ "$thorough" = "1" ]; then
gitcredfiles=`find / -name ".git-credentials" 2>/dev/null`
	if [ "$gitcredfiles" ]; then
  		echo -e "${_yellow}[+] Git credentials saved on the machine!:${_reset}\n$gitcredfiles"
  		echo -e "\n"
	fi
fi

#list all world-writable files excluding /proc and /sys
if [ "$thorough" = "1" ]; then
wwfiles=`find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwfiles" ]; then
		echo -e "${_red}[-] World-writable files (excluding /proc and /sys):${_reset}\n$wwfiles" 
		echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wwfiles" ]; then
		mkdir $format/ww-files/ 2>/dev/null
		for i in $wwfiles; do cp --parents $i $format/ww-files/; done 2>/dev/null
	fi
fi

#are any .plan files accessible in /home (could contain useful information)
usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$usrplan" ]; then
  echo -e "${_red}[-] Plan file permissions and contents:${_reset}\n$usrplan" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$usrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $usrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
fi

bsdusrplan=`find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$bsdusrplan" ]; then
  echo -e "${_red}[-] Plan file permissions and contents:${_reset}\n$bsdusrplan" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$bsdusrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $bsdusrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
fi

#are there any .rhosts files accessible - these may allow us to login as another user etc.
rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostsusr" ]; then
  echo -e "${_yellow}[+] rhost config file(s) and file contents:${_reset}\n$rhostsusr" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$rhostsusr" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

bsdrhostsusr=`find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$bsdrhostsusr" ]; then
  echo -e "${_yellow}[+] rhost config file(s) and file contents:${_reset}\n$bsdrhostsusr" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$bsdrhostsusr" ]; then
  mkdir $format/rhosts 2>/dev/null
  for i in $bsdrhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostssys" ]; then
  echo -e "${_yellow}[+] Hosts.equiv file and contents: ${_reset}\n$rhostssys" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$rhostssys" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostssys; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

#list nfs shares/permisisons etc.
nfsexports=`ls ${_color_flag} -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null`
if [ "$nfsexports" ]; then
  echo -e "${_red}[-] NFS config details: ${_reset}\n$nfsexports" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$nfsexports" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/exports $format/etc-export/exports 2>/dev/null
fi

if [ "$thorough" = "1" ]; then
  #phackt
  #displaying /etc/fstab
  fstab=`cat /etc/fstab 2>/dev/null`
  if [ "$fstab" ]; then
    echo -e "${_red}[-] NFS displaying partitions and filesystems - you need to check if exotic filesystems${_reset}"
    echo -e "$fstab"
    echo -e "\n"
  fi
fi

#looking for credentials in /etc/fstab
fstab=`grep username /etc/fstab 2>/dev/null |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo username: 2>/dev/null; grep password /etc/fstab 2>/dev/null |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; grep domain /etc/fstab 2>/dev/null |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null`
if [ "$fstab" ]; then
  echo -e "${_yellow}[+] Looks like there are credentials in /etc/fstab!${_reset}\n$fstab"
  echo -e "\n"
fi

if [ "$export" ] && [ "$fstab" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
fi

fstabcred=`grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null`
if [ "$fstabcred" ]; then
    echo -e "${_yellow}[+] /etc/fstab contains a credentials file!${_reset}\n$fstabcred" 
    echo -e "\n"
fi

if [ "$export" ] && [ "$fstabcred" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
fi

#use supplied keyword and cat *.conf files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  echo -e "[-] Can't search *.conf files as no keyword was entered\n" 
  else
    confkey=`find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$confkey" ]; then
      echo -e "${_red}[-] Find keyword ($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears):${_reset}\n$confkey" 
      echo -e "\n" 
     else 
	echo -e "${_red}[-] Find keyword ($keyword) in .conf files (recursive 4 levels):${_reset}" 
	echo -e "'$keyword' not found in any .conf files" 
	echo -e "\n" 
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$confkey" ]; then
	  confkeyfile=`find / -maxdepth 4 -name *.conf -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/config_files/ 2>/dev/null
      for i in $confkeyfile; do cp --parents $i $format/keyword_file_matches/config_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.php files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  echo -e "[-] Can't search *.php files as no keyword was entered\n" 
  else
    phpkey=`find / -maxdepth 10 -name *.php -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$phpkey" ]; then
      echo -e "${_red}[-] Find keyword ($keyword) in .php files (recursive 10 levels - output format filepath:identified line number where keyword appears):${_reset}\n$phpkey" 
      echo -e "\n" 
     else 
  echo -e "${_red}[-] Find keyword ($keyword) in .php files (recursive 10 levels):${_reset}" 
  echo -e "'$keyword' not found in any .php files" 
  echo -e "\n" 
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$phpkey" ]; then
    phpkeyfile=`find / -maxdepth 10 -name *.php -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/php_files/ 2>/dev/null
      for i in $phpkeyfile; do cp --parents $i $format/keyword_file_matches/php_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "[-] Can't search *.log files as no keyword was entered\n" 
  else
    logkey=`find / -maxdepth 4 -name *.log -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$logkey" ]; then
      echo -e "${_red}[-] Find keyword ($keyword) in .log files (recursive 4 levels - output format filepath:identified line number where keyword appears):${_reset}\n$logkey" 
      echo -e "\n" 
     else 
	echo -e "${_red}[-] Find keyword ($keyword) in .log files (recursive 4 levels):${_reset}" 
	echo -e "'$keyword' not found in any .log files"
	echo -e "\n" 
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$logkey" ]; then
      logkeyfile=`find / -maxdepth 4 -name *.log -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
	  mkdir --parents $format/keyword_file_matches/log_files/ 2>/dev/null
      for i in $logkeyfile; do cp --parents $i $format/keyword_file_matches/log_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "[-] Can't search *.ini files as no keyword was entered\n" 
  else
    inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$inikey" ]; then
      echo -e "${_red}[-] Find keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears):${_reset}\n$inikey" 
      echo -e "\n" 
     else 
	echo -e "${_red}[-] Find keyword ($keyword) in .ini files (recursive 4 levels):${_reset}" 
	echo -e "'$keyword' not found in any .ini files" 
	echo -e "\n"
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$inikey" ]; then
	  inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/ini_files/ 2>/dev/null
      for i in $inikey; do cp --parents $i $format/keyword_file_matches/ini_files/ ; done 2>/dev/null
  fi
fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null`
if [ "$allconf" ]; then
  echo -e "${_red}[-] All *.conf files in /etc (recursive 1 level):${_reset}\n$allconf" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$allconf" ]; then
  mkdir $format/conf-files/ 2>/dev/null
  for i in $allconf; do cp --parents $i $format/conf-files/; done 2>/dev/null
fi

# retrieves accessible history file paths (e.g. ~/.bash_history, ~/.wget-hsts, ~/.lesshst, ecc.)
# from users with valid home directories and shells
for entry in $(grep "sh$" /etc/passwd); do
    user=`echo $entry | cut -d":" -f1`
    home=`echo $entry | cut -d":" -f6`
    usrhist=`ls ${_color_flag} -la $home/.*_history $home/.*-hsts $home/.*hst 2>/dev/null`
    echo -en "${_red}[-] ${_yellow}${user}${_red}'s history files:${_reset}"
    if [ "$usrhist" ]; then
        echo -e "\n$usrhist\n"
        
        # if requested we export history files
        if [ "$export" ] && [ "$usrhist" ]; then
            # create dir only if it does not exist
            mkdir -p $format/history_files/ 2>/dev/null
            for f in $usrhist; do cp --parents $f $format/history_files/; done 2>/dev/null
        fi
        
    else
        echo -e " ${_yellow}Not found.${_reset}\n"
    fi
done

#all accessible .bash_history files in /home
checkbashhist=`find /home -name .bash_history -print -exec cat {} 2>/dev/null \;`
if [ "$checkbashhist" ]; then
  echo -e "${_red}[-] Location and contents (if accessible) of .bash_history file(s):${_reset}\n$checkbashhist"
  echo -e "\n"
fi

#any .bak files that may be of interest
bakfiles=`find / -name *.bak -type f 2</dev/null`
if [ "$bakfiles" ]; then
  echo -e "${_red}[-] Location and Permissions (if accessible) of .bak file(s):${_reset}"
  for bak in `echo $bakfiles`; do ls -la $bak;done
  echo -e "\n"
fi

#is there any mail accessible
readmail=`ls ${_color_flag} -la /var/mail 2>/dev/null`
if [ "$readmail" ]; then
  echo -e "${_red}[-] Any interesting mail in /var/mail:${_reset}\n$readmail" 
  echo -e "\n"
fi

#can we read roots mail
readmailroot=`head /var/mail/root 2>/dev/null`
if [ "$readmailroot" ]; then
  echo -e "${_yellow}[+] We can read /var/mail/root! (snippet below)${_reset}\n$readmailroot" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readmailroot" ]; then
  mkdir $format/mail-from-root/ 2>/dev/null
  cp $readmailroot $format/mail-from-root/ 2>/dev/null
fi
}

docker_checks()
{

#specific checks - check to see if we're in a docker container
dockercontainer=` grep ${_color_flag} -i docker /proc/self/cgroup  2>/dev/null; find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null`
if [ "$dockercontainer" ]; then
  echo -e "${_yellow}[+] Looks like we're in a Docker container:${_reset}\n$dockercontainer" 
  echo -e "\n"
fi

#specific checks - check to see if we're a docker host
dockerhost=`docker --version 2>/dev/null; docker ps -a 2>/dev/null`
if [ "$dockerhost" ]; then
  echo -e "${_yellow}[+] Looks like we're hosting Docker:${_reset}\n$dockerhost" 
  echo -e "\n"
fi

#specific checks - are we a member of the docker group
dockergrp=`id | grep ${_color_flag} -i docker 2>/dev/null`
if [ "$dockergrp" ]; then
  echo -e "${_yellow}[+] We're a member of the (docker) group - could possibly misuse these rights!${_reset}\n$dockergrp" 
  echo -e "\n"
fi

#specific checks - are there any docker files present
dockerfiles=`find / -name Dockerfile -exec ls -l {} 2>/dev/null \;`
if [ "$dockerfiles" ]; then
  echo -e "${_red}[-] Anything juicy in the Dockerfile:${_reset}\n$dockerfiles" 
  echo -e "\n"
fi

#specific checks - are there any docker files present
dockeryml=`find / -name docker-compose.yml -exec ls -l {} 2>/dev/null \;`
if [ "$dockeryml" ]; then
  echo -e "${_red}[-] Anything juicy in docker-compose.yml:${_reset}\n$dockeryml" 
  echo -e "\n"
fi
}

lxc_container_checks()
{

#specific checks - are we in an lxd/lxc container
lxccontainer=`grep ${_color_flag} -qa container=lxc /proc/1/environ 2>/dev/null`
if [ "$lxccontainer" ]; then
  echo -e "${_yellow}[+] Looks like we're in a lxc container:${_reset}\n$lxccontainer"
  echo -e "\n"
fi

#specific checks - are we a member of the lxd group
lxdgroup=`id | grep ${_color_flag} -i lxd 2>/dev/null`
if [ "$lxdgroup" ]; then
  echo -e "${_yellow}[+] We're a member of the (lxd) group - could possibly misuse these rights!${_reset}\n$lxdgroup"
  echo -e "\n"
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
