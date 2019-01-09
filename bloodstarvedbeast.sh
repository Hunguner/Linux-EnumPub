input=$@
Perl=$(whereis perl | cut -d: -f2)
Python=$(whereis python | cut -d: -f2)
Gcc=$(whereis gcc | cut -d: -f2)
Cc=$(whereis cc | cut -d: -f2)
Wget=$(whereis wget | cut -d: -f2)
Nc=$(whereis nc | cut -d: -f2)
Netcat=$(whereis netcat | cut -d: -f2)
Tftp=$(whereis tftp | cut -d: -f2)
Ftp=$(whereis ftp | cut -d: -f2)
if [[ $input == "" ]] || [[ $input == "help" ]] || [[ $input == "list" ]]
then
	echo -e "\e[34mPossible Commands\e[0m"
	echo "-----------------------------------------------------"
	echo -e "\e[31mUID:\e[0m" "Lists the SUID and GUID"
	echo -e "\e[31mUsers:\e[0m" "Shows User info"
	echo -e "\e[31mlusers:\e[0m" "List all Users"
	echo -e "\e[31mlgroups:\e[0m" "List all Groups"
	echo -e "\e[31mKernel:\e[0m" "Shows Kernel info"
	echo -e "\e[31mNetwork:\e[0m" "Shows Network info"
	echo -e "\e[31mServices:\e[0m" "Lists services run by root and current user"
	echo -e "\e[31mJobs:\e[0m" "Lists current jobs(hourly,daily,monthly)"
	echo -e "\e[31mWorld:\e[0m" "Lists world writable files and directories"
	echo -e "\e[31mPriv:\e[0m" "Shows any Privileged info the current user might have access to"
	echo -e "\e[31mPrep:\e[0m" "Show coding laguages and tools to help file transfer"
	echo -e "\e[31mSSH:\e[0m" "Shows SSH keys and any other infomation"
	echo -e "\e[31mPrograms:\e[0m" "Shows programs and their versions"\\n

elif [[ $input == "UID" ]] || [[ $input == "uid" ]]
then
	echo -e "\e[34mUID list(SUID and GUID)\e[0m"
	echo -e "--------------------------------------------------------------------------"\\n
	echo -e "\e[31mUID and GID of each user:\e[0m"
	for i in $(cat /etc/passwd 2>/dev/null| cut -d":" -f1 2>/dev/null);do id $i;done 2>/dev/null
	echo -e "\e[31mSUID:\e[0m"
	find / -perm -4000 2>/dev/null
	echo -e \\n
	echo -e "\e[31mGUID:\e[0m"
	find / -perm -2000 2>/dev/null

elif [[ $input == "users" ]] || [[ $input == "Users" ]]
then
	echo -e "\e[34mUser Infomation\e[0m"
	echo -e "-------------------------------------------------------------------------"\\n
	echo -e "\e[31mBash History:\e[0m"
	cat ~/.bash_history
	echo -e "\e[31mCurrent User:\e[0m" $(whoami) $(id)
	echo -e "\e[31mUsers Logged In:\e[0m"
	w
	echo -e "\e[31mSuper Users:\e[0m" $(grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}')

elif [[ $input == "lusers" ]]
then
	echo -e "\e[34mList of Users\e[0m"
	echo -e "--------------------------------------------------------"\\n
	echo -e "\e[31mUsers:\e[0m"
	cut -d: -f1 /etc/passwd

elif [[ $input == "lgroups" ]]
then
	echo -e "\e[34mList of Groups\e[0m"
	echo -e "--------------------------------------------------------"\\n
	echo -e "\e[31mGroups:\e[0m"
	cut -d: -f1 /etc/group

elif [[ $input == "Kernel" ]] || [[ $input == "kernel" ]]
then
	echo -e "\e[34mKernel Infomation\e[0m"
	echo -e "---------------------------------------------------------------------------"\\n
	echo -e "\e[31mKernel Info:\e[0m" $(cat /proc/version)\\n
	echo -e "\e[31mSystem Info:\e[0m" $(uname -a)\\n
	echo -e "\e[31mKernel Release:\e[0m" $(uname -r)\\n
	echo -e "\e[31mHostname:\e[0m" $(uname -n)\\n
	echo -e "\e[31mArchitecture:\e[0m" $(uname -m)\\n
	echo -e "\e[31mFile System Info:\e[0m" $(df -a)\\n
 	echo -e "\e[31mDistribution Info:\e[0m"
	cat /etc/*-release

elif [[ $input == "network" ]] || [[ $input == "Network" ]]
then
	echo -e "\e[34mNetwork Infomation\e[0m"
	echo -e "---------------------------------------------------------------------------"\\n
	echo -e "\e[31mResolv.conf:\e[0m"
	cat /etc/resolv.conf
	echo -e \\n
	echo -e "\e[31mNetworks:\e[0m"
	cat /etc/networks
	echo -e "\e[31mIptables:\e[0m"
	iptables -L
	echo -e \\n
	echo -e "\e[31mDNS Domain Name:\e[0m" $(dnsdomainname)\\n
	echo -e "\e[31mConnections:\e[0m"
	lsof -i
	echo -e \\n
	echo -e "\e[31mActive Connections:\e[0m"
	netstat -tulpn
	echo -e \\n
	echo -e "\e[31mARP Cache:\e[0m"
	arp -e
	echo -e \\n
	echo -e "\e[31mKernel Route Table:\e[0m"
	route
	echo -e \\n
	echo -e "\e[31mPrinters:\e[0m"
	lpstat -a

elif [[ $input == "services" ]] || [[ $input == "Services" ]]
then
	echo -e "\e[34mList of Services\e[0m"
	echo -e "---------------------------------------------------------------------------"\\n
	echo -e "\e[31mServices run by root:\e[0m"
	ps aux | grep root
	echo -e \\n
	echo -e "\e[31mServices run by current user:\e[0m"
	ps aux | grep $(whoami)

elif [[ $input == "Jobs" ]] || [[ $input == "jobs" ]]
then
	echo -e "\e[34mList of Jobs\e[0m"
	echo -e "---------------------------------------------------------------------------"\\n
	echo -e "\e[31mCron Jobs:\e[0m" 
	ls -la /etc/cron*
	echo -e "\e[31mRun \e[34mtop\e[0m \e[31mto view current tasks\e[0m"

elif [[ $input == "World" ]] || [[ $input == "world" ]]
then
	echo -e "\e[34mWorld Writable Folders and Files\e[0m"
	echo -e "---------------------------------------------------------"\\n
	echo -e "\e[31mWorld Writable Folders:\e[0m"
	find / -perm -222 -type -d 2>/dev/null
	echo -e \\n
	echo -e "\e[31mWorld Writable Files:\e[0m"
	find / -perm -222 -type f 2>/dev/null
	echo -e \\n
	echo -e "\e[31mFor No Owner Files Run:\e[0m find / \! -nouser 2>/dev/null"

elif [[ $input == "Priv" ]] || [[ $input == "priv" ]] 
then

	echo -e "\e[34mPrivilege Info\e[0m"
	echo -e "---------------------------------------------"\\n
	echo -e "\e[31mPasswd:\e[0m"
	cat /etc/passwd
	echo -e \\n
	echo -e "\e[31mShadow:\e[0m"
	cat /etc/shadow
	echo -e \\n
	echo -e "\e[31mGroup:\e[0m"
	cat /etc/group
	echo -e \\n
	echo -e "\e[31mSudoers:\e[0m"
	cat /etc/sudoers
	echo -e \\n

elif [[ $input == "Prep" ]] || [[ $input == "prep" ]]
then

	echo -e "\e[34mLanguages Available\e[0m"
	echo -e "--------------------------------------------"\\n
	if [[ -z $Perl ]]
	then
		echo -e "\e[31mPerl:\e[0m""No"
	else
		echo -e "\e[31mPerl:\e[0m""Yes"
	fi

	if [[ -z $Python ]]
        then
                echo -e "\e[31mPython:\e[0m""No"
        else
                echo -e "\e[31mPython:\e[0m""Yes"
        fi

	if [[ -z $Gcc ]]
        then
                echo -e "\e[31mGCC:\e[0m""No"
        else
                echo -e "\e[31mGCC:\e[0m""Yes"
        fi

	if [[ -z $Cc ]]
        then
                echo -e "\e[31mC:\e[0m""No"\\n
        else
                echo -e "\e[31mC:\e[0m""Yes"\\n
        fi
	echo -e "\e[34mFile Transfer Options\e[0m"
	echo -e "---------------------------------------"\\n
	if [[ -z $Wget ]]
        then
                echo -e "\e[31mWget:\e[0m""No"
        else
                echo -e "\e[31mWget:\e[0m""Yes"
        fi
        if [[ -z $Nc ]]
        then
                echo -e "\e[31mNC:\e[0m""No"
        else
                echo -e "\e[31mNC:\e[0m""Yes"
        fi
        if [[ -z $Netcat ]]
        then
                echo -e "\e[31mNetcat:\e[0m""No"
        else
                echo -e "\e[31mNetcat:\e[0m""Yes"
        fi
        if [[ -z $Tftp ]]
        then
                echo -e "\e[31mTFTP:\e[0m""No"
        else
                echo -e "\e[31mTFTP:\e[0m""Yes"
        fi
        if [[ -z $Ftp ]]
        then
                echo -e "\e[31mFTP:\e[0m""No"\\n
        else
                echo -e "\e[31mFTP:\e[0m""Yes"\\n
        fi

elif [[ $input == "ssh" ]] || [[ $input == "SSH" ]]
then

	echo -e "\e[34mSSH infomation\e[0m"
	echo -e "------------------------------------------"\\n
	echo -e "\e[31mKnown Hosts:\e[0m"
	cat ~/.ssh/known_hosts
	echo -e \\n
	echo -e "\e[31mAuthorized_keys:\e[0m"
	cat ~/.ssh/authorized_keys
	echo -e \\n
	echo -e "\e[31mID RSA:\e[0m"
	cat ~/.ssh/id_rsa
	echo -e \\n
	echo -e "\e[31mSSH Config:\e[0m"
	cat /etc/ssh/ssh_config
	echo -e \\n
	echo -e "\e[31mSSHD Config:\e[0m"
	cat /etc/ssh/sshd_config
	echo -e \\n
	echo -e "\e[31mPrivate RSA Key:\e[0m"
	cat /etc/ssh/ssh_host_rsa_key

elif [[ $input == "programs" ]] || [[ $input == "Programs" ]]
then

	echo -e "\e[34mProgram Info\e[0m"
	echo -e "------------------------------------------------"\\n
	echo -e "\e[31mPrograms from /usr/bin:\e[0m"
	ls -lah /usr/bin
	echo -e \\n
	echo -e "\e[31mPrograms from /var/cache/apt/archives/:\e[0m"
	ls -lah /var/cache/apt/archives
	echo -e \\n
	echo -e "\e[31mPrograms from /var/cache/apt/archives0:\e[0m"
	ls -lah /var/cache/apt/archives0
	echo -e \\n
	echo -e "\e[31mPrograms from /var/cache/yum:\e[0m"
	ls -lah /var/cache/yum
	echo -e \\n
fi
