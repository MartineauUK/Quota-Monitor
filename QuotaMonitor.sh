#!/bin/sh
VER="v1.04"
#======================================================================================= © 2018 Martineau v1.04
#
# Monitor device traffic quotas and apply block if limit exceeded
#
#    QuotaMonitor     [help | -h] ['ip='{[ip_address[,...] | hostname[...] | auto | all ]} ['remove']] ['init'[qos]] ['reset' | 'resetdel'] ['unblock'] ['zero']
#                     ['monitor'] ['interval='{interval_seconds}] ['dlimit={interval_limit}'] ['ulimit={interval_limit}']  ['quota='['rx'|'tx'|'used']]
#                     ['cap='{cap_limit}] ['ignorezero'] ['actionrx='{script_name}] ['actiontx='{script_name}] ['actionused='{script_name}] ['nolog'] ['qos']
#                     ['report='{path_for_quota.csv}] ['once'] ['status'[ 'verbose']]
#
#    QuotaMonitor     init
#                     Create the two Quota Monitor Chains (MyQUOTAi/MyQUOTA) for DOWNLOAD/UPLOAD
#                     Individual device Quota limits may be defined in '/jffs/configs/QuotaLimits' but will be ignored if 'dlimit='/'ulimit=' specified
#                     e.g.
#                         #Hostname      Rx     Tx     Cap
#                         HP-Envy13   300MB   20MB   100GB
#                     NOTE: Quota limits may only be applied to the same 'interval=' value
#    QuotaMonitor     status
#                     Show the contents of the two Chains. The USED var is derived from the RECV/XMIT byte count!
#    QuotaMonitor     ip=192.168.1.123,iphone,laptop
#                     Add three devices to be monitored
#    QuotaMonitor     ip=auto
#                     Attempt to auto discover all LAN devices and add them to the monitor list.
#    QuotaMonitor     monitor
#                     Start Rx/Tx and Total Used quota monitoring for the devices defined (default limits 50MB in 60 secs Capped @50GB)
#                     If the limits are exceeded, then the device is BLOCKED.
#    QuotaMonitor     monitor interval=10 dlimit=5mb cap=100MB
#                     Start Start Rx/Tx and Total Used quota monitoring for the devices defined in the Chains (uses 5MB in 10 secs Capped @100MB)
#    QuotaMonitor     monitor interval=10 dlimit=5mb cap=100MB ignorezero quota=
#                     Start Start Rx/Tx and Total Used quota monitoring for the devices, but devices which have not received/transmitted data are not displayed.
#                     This mode is useful for identifying suitable quota limits, as no quota metric (Rx,Tx or Used) is enforced
#                     Useful for testing, to prove if the Quota limits can be ENFORCED in real-time
#    QuotaMonitor     monitor actionRx=Quota_Rx.sh
#                     Start the Rx/Tx and Total Used Quota monitoring, but rather than BLOCK the device if the Rx quota is exceeded run script Quota_Rx.sh
#    QuotaMonitor     monitor qos
#                     Start the Rx/Tx and Total Used Quota monitoring, but rather than BLOCK the device if the Rx quota is exceeded apply QoS rules
#                     NOTE: 'initqos' must have been previously specified.
#    QuotaMonitor     ip=laptop unblock
#                     Unblock a specified device.
#    QuotaMonitor     ip=all unblockqos
#                     Unblock ALL devices that are currently throttled by QoS.
#    QuotaMonitor     ip=laptop remove
#                     Remove the device 'laptop' from the Quota Monitoring.
#                     NOTE: This will require a second instance of the script to allow uninterrupted monitoring
#    QuotaMonitor     reset
#                     Removes all devices from monitoring but retains the Chains.
#    QuotaMonitor     resetdel
#                     Deletes both chains and all iptables rules
#    QuotaMonitor     zero
#                     Resets the Quota counts to 0. Could be scheduled by a cron job every day @00:00 etc.
#    QuotaMonitor     monitor nolog
#                     Start the Rx/Tx and Total Used Quota monitoring, but do not record the output to Syslog
#    QuotaMonitor     monitor nolog report=/tmp/mnt/xxx/Quota.csv once quota=
#                     Start the Rx/Tx and Total Used Quota monitoring, but do not record the output to Syslog, instead write the results to '/tmp/mnt/xxx/Quota.csv'
#                     NOTE: **WARNING" If you schedule it via cron with the 'once' option YOU MUST SPECIFY 'quota=' otherwise it may apply the Quota BLOCK!


# The chains counts may be reset usually at midnight then 'interval=86400' might be appropriate
#

# [URL="https://www.snbforums.com/threads/edit-real-time-quota-monitoring-download-upload-data-used.50066/"][EDIT]Real-time Quota Monitoring (Download/Upload/Data Used)[/URL]

#
# Thanks to forum member @FreshJR for providing the following throttle rules if applying a BLOCK is too harsh! ;-)
#
	##upload
		# iptables -D POSTROUTING -t mangle -o eth0 -s 192.168.2.100/32 -m mark --mark 0x40000000/0xc0000000 -j MARK --set-mark 0x403FFFFF
		# iptables -A POSTROUTING -t mangle -o eth0 -s 192.168.2.100/32 -m mark --mark 0x40000000/0xc0000000 -j MARK --set-mark 0x403FFFFF
		# tc class add dev eth0 parent 1:1 classid 1:100 htb prio 8 rate 1500kbit ceil 1500kbit
		# tc qdisc add dev eth0 parent 1:100 handle 100: sfq
		# tc filter add dev eth0 parent 1: protocol all prio 50 u32 match mark 0x403FFFFF 0xC03FFFFF flowid 1:100

	##download
		# iptables -D POSTROUTING -t mangle -o br0 -d 192.168.2.100/32 -m mark --mark 0x80000000/0xc0000000 -j MARK --set-mark 0x803FFFFF
		# iptables -A POSTROUTING -t mangle -o br0 -d 192.168.2.100/32 -m mark --mark 0x80000000/0xc0000000 -j MARK --set-mark 0x803FFFFF
		# tc class add dev br0 parent 1:1 classid 1:100 htb prio 8 rate 1500kbit ceil 1500kbit
		# tc qdisc add dev br0 parent 1:100 handle 100: sfq
		# tc filter add dev br0 parent 1: protocol all prio 50 u32 match mark 0x803FFFFF 0xC03FFFFF flowid 1:100

Say(){
   echo -e $$ $@ | logger -st "($(basename $0))"
}
SayT(){
   echo -e $$ $@ | logger -t "($(basename $0))"
}
# Print between line beginning with'#==' to first blank line inclusive
ShowHelp() {
	/usr/bin/awk '/^#==/{f=1} f{print; if (!NF) exit}' $0
}
ANSIColours() {

	cRESET="\e[0m";cBLA="\e[30m";cRED="\e[31m";cGRE="\e[32m";cYEL="\e[33m";cBLU="\e[34m";cMAG="\e[35m";cCYA="\e[36m";cGRA="\e[37m";cFGRESET="\e[39m"
	cBGRA="\e[90m";cBRED="\e[91m";cBGRE="\e[92m";cBYEL="\e[93m";cBBLU="\e[94m";cBMAG="\e[95m";cBCYA="\e[96m";cBWHT="\e[97m"
	aBOLD="\e[1m";aDIM="\e[2m";aUNDER="\e[4m";aBLINK="\e[5m";aREVERSE="\e[7m"
	aBOLDr="\e[21m";aDIMr="\e[22m";aUNDERr="\e[24m";aBLINKr="\e[25m";aREVERSEr="\e[27m"
	cWRED="\e[41m";cWGRE="\e[42m";cWYEL="\e[43m";cWBLU="\e[44m";cWMAG="\e[45m";cWCYA="\e[46m";cWGRA="\e[47m"

	cYBLU="\e[93;48;5;21m"

	xHOME="\e[H";xERASE="\e[2J";xERASEDOWN="\e[J";xERASEUP="\e[1J";xCSRPOS="\e[s";xPOSCSR="\e[u";xERASEEOL="\e[K"
}
# Function Parse(String delimiter(s) variable_names)
Parse() {
	#
	# 	Parse		"Word1,Word2|Word3" ",|" VAR1 VAR2 REST
	#				(Effectivley executes VAR1="Word1";VAR2="Word2";REST="Word3")

	local string IFS

	TEXT="$1"
	IFS="$2"
	shift 2
	read -r -- "$@" <<EOF
$TEXT
EOF
}
Convert_SECS_to_HHMMSS() {

	local SECS=$1

	local DAYS_TXT=
	if [ $SECS -ge 86400 ] && [ ! -z "$2" ];then				# More than 24:00 i.e. 1 day?
		local DAYS=$((${SECS}/86400))
		SECS=$((SECS-DAYS*86400))
		local DAYS_TXT=$DAYS" days"
	fi
	local HH=$((${SECS}/3600))
	local MM=$((${SECS}%3600/60))
	local SS=$((${SECS}%60))
	if [ -z $2 ];then
		echo $(printf "%02d:%02d:%02d" $HH $MM $SS)					# Return 'hh:mm:ss" format
	else
		echo $(printf "%s %02d:%02d:%02d" "$DAYS_TXT" $HH $MM $SS)		# Return in "x days hh:mm:ss" format
	fi
}
GotoXY() {
	local ROW=$1
	local COL=$2

	echo -en "\e[$ROW;${COL}f"
}
StatusLine() {

	local ACTION=$1
	local FLASH="$aBLINK"

	if [ "${ACTION:0:7}" != "NoANSII" ];then

		[ "${ACTION:0:7}" == "NoFLASH" ] && local FLASH=

		local TEXT=$2

		echo -en $xCSRPOS								# Save current cursor position

		case $ACTION in
			*Clear*)	echo -en ${xHOME}${cRESET}$xERASEEOL;;
			*)			echo -en ${xHOME}${aBOLD}${FLASH}${xERASEEOL}$TEXT;;
		esac

		echo -en $xPOSCSR								# Restore previous cursor position
	fi

}
Get_WAN_IF_Name() {

	local IF_NAME=$(nvram get wan0_ifname)				# DHCP/Static ?

	# Usually this is probably valid for both eth0/ppp0e ?
	if [ "$(nvram get wan0_gw_ifname)" != "$IF_NAME" ];then
		local IF_NAME=$(nvram get wan0_gw_ifname)
	fi

	if [ ! -z "$(nvram get wan0_pppoe_ifname)" ];then
		local IF_NAME="$(nvram get wan0_pppoe_ifname)"		# PPPoE
	fi

	echo $IF_NAME

}
Chain_exists() {

	# Args: {chain_name} [table_name]

    local CHAIN="$1"
	shift

    [ $# -eq 1 ] && local TABLE="-t $1"

    iptables $TABLE -n -L $CHAIN >/dev/null 2>&1
	local RC=$?
	if [ $RC -ne 0 ];then
		echo "N"
		return 1
	else
		echo "Y"
		return 0
	fi
}
Is_Private_IPv4 () {
	# 127.  0.0.0 – 127.255.255.255     127.0.0.0 /8
	# 10.   0.0.0 –  10.255.255.255      10.0.0.0 /8
	# 172. 16.0.0 – 172. 31.255.255    172.16.0.0 /12
	# 192.168.0.0 – 192.168.255.255   192.168.0.0 /16
	#grep -oE "(^192\.168\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)|(^172\.([1][6-9]|[2][0-9]|[3][0-1])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)|(^10\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)"
	grep -oE "(^127\.)|(^(0)?10\.)|(^172\.(0)?1[6-9]\.)|(^172\.(0)?2[0-9]\.)|(^172\.(0)?3[0-1]\.)|(^169\.254\.)|(^192\.168\.)"
}
Convert_TO_IP () {

	# Perform a lookup if a hostname (or I/P address) is supplied and is not known to PING
	# NOTE: etc/host.dnsmasq is in format
	#
	#       I/P address    hostname
	#

	local USEPATH="/jffs/configs"

	if [ -n "$1" ];then

		if [ -z $2 ];then									# Name to IP Address
		   local IP_NAME=$(echo $1 | tr '[a-z]' '[A-Z]')

		   #local IP_RANGE=$(ping -c1 -t1 -w1 $IP_NAME 2>&1 | tr -d '():' | awk '/^PING/{print $3}')
		   #local IP_RANGE=$(ping -c 1 -t 1 $IP_NAME | head -1 | cut -d ' ' -f 3 | tr -d '()')
		   local IP_RANGE=$(nslookup "$IP_NAME" | tail -n 1 | cut -d' ' -f3)  # Prevent rogue devices slowing us down


		   # 127.0.53.53 for ANDROID? https://github.com/laravel/valet/issues/115
		   if [ -n "$(echo $IP_RANGE | grep -E "^127")" ];then
			  local IP_RANGE=
		   fi

		   if [ -z "$IP_RANGE" ];then		# Not PINGable so lookup static

			  IP_RANGE=$(grep -i "$IP_NAME" /etc/hosts.dnsmasq  | awk '{print $1}')
			  #logger -s -t "($(basename $0))" $$ "Lookup '$IP_NAME' in DNSMASQ returned:>$IP_RANGE<"

			  # If entry not matched in /etc /hosts.dnsmasq see if it exists in our IPGroups lookup file
			  #
			  #       KEY     I/P address[ {,|-} I/P address]
			  #
			  if [ -z "$IP_RANGE" ] && [ -f $USEPATH/IPGroups ];then
				 #IP_RANGE=$(grep -i "^$IP_NAME" $USEPATH/IPGroups | awk '{print $2}')
				 IP_RANGE=$(grep -i "^$IP_NAME" $USEPATH/IPGroups  | awk '{$1=""; print $0}')	# All columns except 1st to allow '#comments' and
	#																									#     spaces and ',' between IPs v1.07
				 #logger -s -t "($(basename $0))" $$ "Lookup '$IP_NAME' in '$USEPATH/IPGroups' returned:>$IP_RANGE<"
			  fi
		   fi
		else												# IP Address to name
			IP_RANGE=$(nslookup $1 | grep "Address" | grep -v localhost | cut -d" " -f4)
		fi
	else
	   local IP_RANGE=									# Return a default WiFi Client????
	   #logger -s -t "($(basename $0))" $$ "DEFAULT '$IP_NAME' lookup returned:>$IP_RANGE<"
	fi

	echo $IP_RANGE
}
Hostname_from_IP () {

	local HOSTNAMES=

	for IP in $@
		do
			local HOSTNAME=$(Convert_TO_IP "$IP" "Reverse")
			HOSTNAMES=$HOSTNAMES" "$HOSTNAME
		done
	echo $HOSTNAMES
}
Get_Current_Bytes() {
	echo $(iptables --line -nvxL $2 | grep -v "Block" | grep "$1" | awk '{print $3}')
	return 0
}
Convert_1024KMG() {

	local NUM=$(echo "$1" | tr [a-z] [A-Z])

	if [ ! -z "$(echo $NUM | grep -oE "B|K|KB|M|MB|G|GB")" ];then
		case "$(echo $NUM | grep -oE "B|K|KB|M|MB|G|GB")" in
			M|MB)
				local NUM=$(echo "$NUM" | tr -d 'MB')
				local NUM=$((NUM*1024*1024))
				;;
			G|GB)
				local NUM=$(echo "$NUM" | tr -d "GB")
				# local NUM=$((NUM*1024*1024*1024))
				local NUM=$(expr "$NUM" \* "1024" \* "1024" \* "1024")
				;;
			K|KB)
				local NUM=$(echo "$NUM" | tr -d "KB")
				local NUM=$((NUM*1024))
				;;
			B)
				local NUM=$(echo "$NUM" | tr -d "B")
				;;
		esac
	else
		NUM=$(echo "$NUM" | tr -dc '0-9')
	fi

	echo $NUM
}
Size_Human() {

	local SIZE=$1
	if [ -z "$SIZE" ];then
		echo "N/A"
		return 1
	fi
	#echo $(echo $SIZE | awk '{ suffix=" KMGT"; for(i=1; $1>1024 && i < length(suffix); i++) $1/=1024; print int($1) substr(suffix, i, 1), $3; }')

	# if [ $SIZE -gt $((1024*1024*1024*1024)) ];then									# 1,099,511,627,776
		# printf "%2.2f TB\n" $(echo $SIZE | awk '{$1=$1/(1024^4); print $1;}')
	# else
		if [ $SIZE -gt $((1024*1024*1024)) ];then										# 1,073,741,824
			printf "%3.2f GB\n" $(echo $SIZE | awk '{$1=$1/(1024^3); print $1;}')
		else
			if [ $SIZE -gt $((1024*1024)) ];then										# 1,048,576
				printf "%3.2f MB\n" $(echo $SIZE | awk '{$1=$1/(1024^2);   print $1;}')
			else
				if [ $SIZE -gt $((1024)) ];then
					printf "%3.2f KB\n" $(echo $SIZE | awk '{$1=$1/(1024);   print $1;}')
				else
					printf "%d Bytes\n" $SIZE
				fi
			fi
		fi
	# fi

	return 0
}
Block_Device() {

	local NAME=$1
	local TIMEBLOCKED=

	local WAN_IF=$(Get_WAN_IF_Name)

	if [ -z "$(iptables --line -nvL $TABLE_IN  | grep -E "Block.*$NAME")" ];then
		iptables -I $TABLE_IN  -d $IP -i $WAN_IF -o br0 -j DROP -m comment --comment "Block $NAME" 	# Block
		iptables -I $TABLE_OUT -s $IP -o $WAN_IF -i br0 -j DROP -m comment --comment "Block $NAME" 	# Block
		TIMEBLOCKED=$(date +%s)									# Epoch seconds
	fi

	echo "$TIMEBLOCKED"

}
QOS_Device() {

	local IP=$1
	local TYPE=$2
	[ "$TYPE" == "Both" ] && TYPE="Tx Rx"
	local TIMEBLOCKED=$(date +%s)

	for DIRECTION in $TYPE										# v1.03
		do
			case $DIRECTION in
				Tx)
					POS=$(iptables --line -t mangle -nvL POSTROUTING 2> /dev/null | grep -E "$IP.*match 0\x4.*BlockQoS" | awk '{print $1}')
					iptables -t mangle -D POSTROUTING $POS 2> /dev/null
					iptables -A POSTROUTING -t mangle -o eth0 -s $IP/32 -m mark --mark 0x40000000/0xc0000000 -j MARK --set-mark 0x403FFFFF -m comment --comment "BlockQoS $HOSTNAME"
					;;
				Rx)
					POS=$(iptables --line -t mangle -nvL POSTROUTING 2> /dev/null | grep -E "$IP.*match 0\x8.*BlockQoS" | awk '{print $1}')
					iptables -t mangle -D POSTROUTING $POS 2> /dev/null
					iptables -A POSTROUTING -t mangle -o br0  -d $IP/32 -m mark --mark 0x80000000/0xc0000000 -j MARK --set-mark 0x803FFFFF -m comment --comment "BlockQoS $HOSTNAME"
					;;
			esac
		done
	echo "$TIMEBLOCKED"
}
EnforceLimits() {

	local STATUS=

	local METRICS=$(echo "$1" | tr ',' ' ')

	local ACTION="Block"

	[ -n "$ALLOW_QOS" ] && local ACTION="QoS"



	# Tacky, uses global variables ;-)


	# NOTE: External script will be requested at every interval...need a semaphore to prevent this????????
	#
	#		Args passed to external script:
	#
	#		"$HOSTNAME" "metric" "metric_value" "metric_limit"
	#
	# e.g.	"HP-Envy13" "Rx"     "123456"       "52428800"

	# Already marked as having previously exceeded quota limits?
	if	[ -z "$(iptables --line -nvxL $TABLE_IN					2>/dev/null | grep -E "Block.*$HOSTNAME")" ]					&& \
		[ -z "$(iptables --line -nvxL $TABLE_OUT				2>/dev/null | grep -E "Block.*$HOSTNAME")" ]					&& \
		[ -z "$(iptables --line -nvxL POSTROUTING -t mangle		2>/dev/null | grep -E "BlockQoS.*$HOSTNAME")" ];then

		for METRIC in $METRICS
			do

				case $METRIC in
					# v1.03 Prioritise the Quota limit check for Rx
					Rx)
						if [ $DELTA_RECV -gt $DLIMIT ];then
							SayT "LAN device $HOSTNAME ($IP) exceeded DOWNLOAD (Rx) Quota Interval limit: $(Size_Human "$DLIMIT")/${INTERVAL}Secs"
							# What is the desired course of Action, External script, Throttle or BLOCK?
							[ -n "$ACTION_RX" ] && ACTION="Run"
							case $ACTION in
								Run)	sh "$ACTION_RX" "$HOSTNAME" "$METRIC" "$DELTA_RECV" "$DLIMIT"
										ACTION=$ACTION_RX
										;;
								QoS)	TIMEBLOCKED=$(QOS_Device "$IP" "Rx")
										eval "${VHOSTNAME}_BLOCKED=$TIMEBLOCKED"
										;;
								Block)	TIMEBLOCKED=$(Block_Device "$HOSTNAME")
										eval "${VHOSTNAME}_BLOCKED=$TIMEBLOCKED"
										;;
							esac
							STATUS=${cBRED}${aREVERSE}"\a*** $ACTION - $METRIC ***"${aREVERSEr}$cRESET
							break														# Don't bother checking other Quotas
						fi
						;;
					Tx)
						if [ $DELTA_XMIT -gt $ULIMIT ];then						# v1.02
							SayT "LAN device $HOSTNAME ($IP) exceeded UPLOAD (Tx) Quota Interval limit: $(Size_Human "$ULIMIT")/${INTERVAL}Secs"
							# What is the desired course of Action, External script, Throttle or BLOCK?
							[ -n "$ACTION_TX" ] && ACTION="Run"
							case $ACTION in
								Run)	sh "$ACTION_TX" "$HOSTNAME" "$METRIC" "$DELTA_XMIT" "$ULIMIT"
										ACTION=$ACTION_TX
										;;
								QoS)	TIMEBLOCKED=$(QOS_Device "$IP" "Tx")
										eval "${VHOSTNAME}_BLOCKED=$TIMEBLOCKED"
										;;
								Block)	TIMEBLOCKED=$(Block_Device "$HOSTNAME")
										eval "${VHOSTNAME}_BLOCKED=$TIMEBLOCKED"
										;;
							esac
							STATUS=${cBRED}${aREVERSE}"\a*** $ACTION - $METRIC ***"${aREVERSEr}$cRESET
							break														# Don't bother checking other Quotas
						fi
						;;

					Used)
						if [ $USED -gt $CAPLIMIT ];then
							SayT "LAN device $HOSTNAME ($IP) exceeded Data Used Capping limit: $(Size_Human "$CAPLIMIT")"
							# What is the desired course of Action, External script, Throttle or BLOCK?
							[ -n "$ACTION_USED" ] && ACTION="Run"
							case $ACTION in
								Run)	sh "$ACTION_USED" "$HOSTNAME" "$METRIC" "$DELTA_XMIT" "$ULIMIT"
										ACTION=$ACTION_USED
										;;
								QoS)	TIMEBLOCKED=$(QOS_Device "$HOSTNAME" "Both")
										eval "${VHOSTNAME}_BLOCKED=$TIMEBLOCKED"
										;;
								Block)	TIMEBLOCKED=$(Block_Device "$HOSTNAME")
										eval "${VHOSTNAME}_BLOCKED=$TIMEBLOCKED"
										;;
							esac
							STATUS=${cBRED}${aREVERSE}"\a*** $ACTION - $METRIC ***"${aREVERSEr}$cRESET
						break														# Don't bother checking other Quotas
						fi
						;;
				esac
			done
	else
		eval "local VTIMESTAMP=\$${VHOSTNAME}_BLOCKED"
		if [ -n "$VTIMESTAMP" ];then
			TIMESTAMP=$(date -d @"$VTIMESTAMP" "+%F %T")
		fi

		if [ "$ACTION" == "QoS" ];then					# Don't use 'Tx'/'Rx' in text other they get BEEPED and MARKED
			[ -n "$(iptables --line -t mangle -nvL POSTROUTING 2> /dev/null | grep -E ".*match 0\x8.*BlockQoS.*$HOSTNAME")" ] && METHOD="IN"
			[ -n "$(iptables --line -t mangle -nvL POSTROUTING 2> /dev/null | grep -E ".*match 0\x4.*BlockQoS.*$HOSTNAME")" ] && METHOD=$METHOD" OUT"
			METHOD=$METHOD", Currently QoS throttled"
		else
			[ -n "$(iptables --line -nvL $TABLE_IN  2> /dev/null | grep -E "Block.*$HOSTNAME")" ] && METHOD="IN"
			[ -n "$(iptables --line -nvL $TABLE_OUT 2> /dev/null | grep -E "Block.*$HOSTNAME")" ] && METHOD=$METHOD" OUT"
			METHOD=$METHOD", Currently BLOCKED"

		fi
		SayT "LAN device $HOSTNAME ($IP) Currently $METHOD $TIMESTAMP"
		STATUS=${cBRED}${METHOD}$TIMESTAMP

	fi

	echo "$STATUS"

}
Setup() {

    eval exec "$FD>$LOCKFILE"
    #Say "Acquiring lock semaphore Setup() '"$LOCKFILE"'"
    flock -x $FD
    #Say "Lock semaphore Setup() acquired '"$LOCKFILE"'"


    iptables -D FORWARD -o br0      -j $TABLE_IN 2>/dev/null
    iptables -D FORWARD -i $WAN_IF  -j $TABLE_OUT 2>/dev/null

    iptables -F $TABLE_IN 2>/dev/null
    iptables -X $TABLE_IN 2>/dev/null
    iptables -F $TABLE_OUT 2>/dev/null
    iptables -X $TABLE_OUT 2>/dev/null

    [ "$1" == "del" ] && return 0

    # Initialise the Quota tables

    iptables -N $TABLE_IN 2>/dev/null                    # Split monitoring into Inbound
    iptables -N $TABLE_OUT 2>/dev/null                   # Split monitoring into Inbound

    iptables -I FORWARD -i br0      -j $TABLE_OUT
    iptables -I FORWARD -i $WAN_IF -j $TABLE_IN

	# Enable 'throttle' QOS rules - Thanks to forum member @FreshJR
	#
	if [ "$ALLOW_QOS" == "AllowQOS" ] && [ -z "$(tc filter show dev br0 | grep "flowid 1:100")" ];then		# v1.03

		##upload
		tc class add dev eth0 parent 1:1 classid 1:100 htb prio 8 rate 1500kbit ceil 1500kbit
		tc qdisc add dev eth0 parent 1:100 handle 100: sfq
		tc filter add dev eth0 parent 1: protocol all prio 50 u32 match mark 0x403FFFFF 0xC03FFFFF flowid 1:100

		##download
		tc class add dev br0 parent 1:1 classid 1:100 htb prio 8 rate 1500kbit ceil 1500kbit
		tc qdisc add dev br0 parent 1:100 handle 100: sfq
		tc filter add dev br0 parent 1: protocol all prio 50 u32 match mark 0x803FFFFF 0xC03FFFFF flowid 1:100

	fi

    flock -u $FD
    #Say "Lock semaphore Setup() released '"$LOCKFILE"'"

}
Colour_RANGE() {

	local SIZE=0
	DEBUG=$3

	[ -n "$1" ] && local SIZE=$1
	[ -n "$2" ] && local MAX=$2

	if [ $SIZE -gt 0 ];then

		local PCT=`expr "$SIZE" \* "100" / "$MAX"`
		#local PCT=$(((SIZE*100)/MAX))

		if [ $PCT -ge 100 ];then
			echo -en ${cRED}${aBOLD}${aREVERSE}${aBLINK}
		else
			if [ $PCT -gt 80 ];then
				echo -en $cRED
			else
				if [ $PCT -gt 75 ];then
					echo -en $cBYEL
				else
					if [ $PCT -gt 50 ];then
						echo -en $cYEL
					else
						if [ $PCT -gt 10 ];then
							echo -en $cBGRE
						else
							[ $PCT -gt 0 ] && echo -en $cGRE || echo -en $cGRE
						fi
					fi
				fi
			fi
		fi
	else
		echo -en $cBGRA
	fi
}
Hold_Scroll_Line() {
	echo -en $xCSRPOS
	echo -en "\e[$TOP_ROW;${ROWS}r"
	echo -en $xPOSCSR
	GotoXY 30 1
	#echo -en $xERASE
	HIGHLIGHT_ROWS=$(echo "$HIGHLIGHT_ROWS" | awk '{$1=""; print $0}' | sed 's/^ *//')
}
Monitor_Client(){

	case "$1" in

		monitor)	echo -e "\n"${cRESET}${cBWHT} $VER" Quota Monitoring....."

				echo -e ${cBMAG}"\n\t"$OPTTXT"\n"$cRESET
				echo -e $cBWHT"\t\t\t${cBCYA}IN/OUT ${cBWHT}Columns Legend : ${cBGRA}0% ${cGRE}<10% ${cBGRE}>10% ${cBYEL}>50% ${cRED}>75% ${cBWHT}and ${cBRED}>80%$cBWHT of Quota limits \n"$cRESET
				printf '\t%b%b%15s %-8s%b %-15s%b%-15s %b%10s %10s %10s %10s %6s %10s %10s\n\n' "$cBCYA" "$cBGRE" "YYYY/MM/DD(Day)" "HH:MM:SS" "$cBCYA" "Host Name" "$cCYA" " IP address" "$cBCYA" "IN" "OUT" "Rx Rate" "Tx Rate" "Per/Sec" "Used" "Data Cap"
				echo -en $cRESET
				MONITORED_DEVICES=

				StatusLine $CMDNOANSII"Update" ${cYBLU}$aBOLD"Collecting Quota monitoring devices....please wait!"

				echo -en $cBRED

				eval exec "$FD>$LOCKFILE"
				#Say "Acquiring lock semaphore Monitor Stage1 '"$LOCKFILE"'"
				flock -x $FD
				#Say "Lock semaphore Monitor Stage1 acquired '"$LOCKFILE"'"

				BAD_CNT=0

				# Create the variables for each of the current defined devices to be Quota monitored
				for HOSTNAME in $(iptables --line -nvxL $TABLE_IN | grep -vE "Chain|pkts" | grep -v "Block" | awk '{print $(NF-1)}')
					do

						if [ -n "$(echo $HOSTNAME | grep -E "\*|/" )" ];then	# v1.03 This is not a valid hostname '/bin' ??????
							BAD_CNT=$((BAD_CNT+1))
							break
						fi

						MONITORED_DEVICES=$MONITORED_DEVICES" "$HOSTNAME

						VHOSTNAME=${HOSTNAME//-/}				# Can't have '-' in Variable names

						if [ "$CMDIGNOREDEVICEQUOTA" != "IgnoreDeviceQuota" ];then	# v1.04
							# Check specific Quota set for device					# v1.04
							if [ -f $FN_QUOTA_LIMITS ];then
								Parse "$(grep -iE "^$HOSTNAME" "$FN_QUOTA_LIMITS")" " " HNAME TXL RXL DATAL
								if [ -n "$HNAME" ] && [ -n "$TXL" ] && [ -n "$RXL" ];then
									eval "${VHOSTNAME}_TX_LIMIT=$(Convert_1024KMG $TXL)"
									eval "${VHOSTNAME}_RX_LIMIT=$(Convert_1024KMG $TXL)"
									eval "${VHOSTNAME}_DATA_LIMIT=$(Convert_1024KMG $DATAL)"
								fi
							fi
						fi

						eval "${VHOSTNAME}_IP=$(Convert_TO_IP ${HOSTNAME})"
						eval "${VHOSTNAME}_BYTES_RECV=$(Get_Current_Bytes $HOSTNAME $TABLE_IN)"		# Current bytes count from iptables
						eval "${VHOSTNAME}_BYTES_XMIT=$(Get_Current_Bytes $HOSTNAME $TABLE_OUT)"	# Current bytes count from iptables
						eval "${VHOSTNAME}_BLOCKED="												# Timestamp when it was blocked in Epoch seconds

					done

				flock -u $FD
				#Say "Lock semaphore Monitor Stage1 released '"$LOCKFILE"'"

				HOST_CNT_BEFORE=$(echo "$MONITORED_DEVICES" | wc -w)
				MONITORED_DEVICES=$(echo "$MONITORED_DEVICES" | sed 's/^ //p')
				# Remove the true hostname and comment duplicate
				MONITORED_DEVICES=$(echo "$MONITORED_DEVICES" | awk '{for (i=1;i<=NF;i++) if (!a[$i]++) printf("%s%s",$i,FS)}')	# Remove duplicates
				HOST_CNT=$(echo "$MONITORED_DEVICES" | wc -w)

				if [ $HOST_CNT_BEFORE -ne $HOST_CNT ];then
					StatusLine $CMDNOANSII"NoFLASH" ${cBRED}${aREVERSE}"\a***ERROR Duplicate HOSTNAMES detected!!"
					return 1						# Halt processing
				fi

				if [ $BAD_CNT -gt 0 ];then									# v1.03
					StatusLine $CMDNOANSII"NoFLASH" ${cBRED}${aREVERSE}"\a***ERROR HOSTNAME '$HOSTNAME' invalid!!"
					return 1						# Halt processing
				fi

				echo -en ${cRESET}$cBBLU

				ELAPSED_SECS2=0									# First time through the loop
				RESULT_PAGECNT=0
				HIGHLIGHT_ROWS=
				CURRENT_ROW=10
				TOP_ROW=10										# Top line of non-scroll window
				SCROLL=99										# Indicates if we are currently physically scrolling ''scroll='

				while true          # Check every $INTERVAL seconds to see if the devices have exceeded their Quota limit
				do

					StatusLine $CMDNOANSII"NoFLASH" ${cBGRE}"Monitoring "$HOST_CNT" Clients...."

					NOW=$(date "+%F(%a) %T")
					START=$(date +%s)								# Adjust the INTERVAL otherwise results look odd! ;-)

					# Experimental scrollable window Rows 10 to 30 i.e 20 records scrolling
					if [ -n "$CMDSCROLL" ] && [ -n "CMDIGNOREZERO" ] && [ -z "$SCROLL_WINDOW" ];then
						echo -en "\e[10;${ROWS}r";GotoXY $TOPROW 1; SCROLL_WINDOW="Scrolling";
					fi

					for HOSTNAME in $MONITORED_DEVICES
						do

							VHOSTNAME=${HOSTNAME//-/}				# Can't have '-' in Variable names

							eval "IP=\$${VHOSTNAME}_IP"

							BLOCKED=$(iptables -nvL $TABLE_IN | grep -oE "Block.*$HOSTNAME")
							RECV=$(Get_Current_Bytes $HOSTNAME $TABLE_IN)
							XMIT=$(Get_Current_Bytes $HOSTNAME $TABLE_OUT)
							USED=$(expr "$RECV" + "$XMIT")
							eval "DELTA_RECV=$((RECV-${VHOSTNAME}_BYTES_RECV))"
							eval "DELTA_XMIT=$((XMIT-${VHOSTNAME}_BYTES_XMIT))"
							eval "${VHOSTNAME}_BYTES_RECV=$RECV"	# Current bytes RECV count
							eval "${VHOSTNAME}_BYTES_XMIT=$XMIT"	# Current bytes XMIT count

							eval "DLIMIT=\$${VHOSTNAME}_RX_LIMIT"		# v1.04
							eval "ULIMIT=\$${VHOSTNAME}_TX_LIMIT"
							eval "CAPLIMIT=\$${VHOSTNAME}_DATA_LIMIT"
							[ -z "$DLIMIT" ] && DLIMIT=$BASE_DLIMIT		# v1.04
							[ -z "$ULIMIT" ] && ULIMIT=$BASE_ULIMIT
							[ -z "$CAPLIMIT" ] && CAPLIMIT=$BASE_CAPLIMIT

							if [ -n "$ENFORCE_QUOTA_METRIC" ];then						# Any quota metrics to be enforced?
								STATUS=$(EnforceLimits "$ENFORCE_QUOTA_METRIC")			# Enforce quota metrics (Rx/Tx/Used)
							fi

							COLOUR_RX=$(Colour_RANGE "$DELTA_RECV" "$DLIMIT" "Rx")
							COLOUR_TX=$(Colour_RANGE "$DELTA_XMIT" "$ULIMIT" "Tx")
							COLOUR_USED=$(Colour_RANGE "$USED" "$CAPLIMIT" "Used")
							ADJUST_TOP_ROW=0
							if [ -n "$(echo "$STATUS" | grep -oE "Rx|Tx|Used")" ];then
								echo -en "\a"$aBOLD						# Highlight the BLOCKED line
								if [ -z "$HIGHLIGHT_ROWS" ];then
									MARK=$((CURRENT_ROW-(TOP_ROW-10)))
									[ $SCROLL -ne 99 ] && MARK=$((MARK-SCROLL))
									[ $CURRENT_ROW -eq 21 ] && MARK=$((MARK-1))
									HIGHLIGHT_ROWS=$(echo $HIGHLIGHT_ROWS" "$MARK | sed 's/^ *//' )
									PREV_MARK=
									ADJUST_TOP_ROW=0
								else
									MARK=$((CURRENT_ROW-(TOP_ROW-10)))
									[ $SCROLL -ne 99 ] && MARK=$((MARK-SCROLL))
									ADJUST_TOP_ROW=$(echo "$HIGHLIGHT_ROWS" | wc -w)
									MARK=$((MARK-ADJUST_TOP_ROW))
									PREV_MARK=$(echo "$HIGHLIGHT_ROWS" | awk '{print $($1)}')
									MARK=$((MARK-PREV_MARK))
									[ $MARK -le 0 ] && MARK=1
									HIGHLIGHT_ROWS=$(echo $HIGHLIGHT_ROWS" "$MARK | sed 's/^ *//' )

								fi
							fi

							# If client BLOCKED then ALWAYS display it!
							if [ -n "$CMDIGNOREZERO" ] && [ $DELTA_RECV -eq 0 ] && [ $DELTA_XMIT -eq 0 ] && [ -z "$BLOCKED" ];then
								continue			# Don't print clients with no RECV/XMIT activity
							fi
							printf "\t%-24s %b%-15s %b%-15s%b%10s%b %b%10s%b %10s %10s %-5s   %b%10s%b %10s %b\n" "$NOW" "$cBWHT" "$HOSTNAME" "$cBBLU" "$IP" "${COLOUR_RX}" "$(Size_Human "$DELTA_RECV")" "${aREVERSEr}${aBLINKr}" "${COLOUR_TX}" "$(Size_Human "$DELTA_XMIT")" "${aREVERSEr}${aBLINKr}${cBWHT}" "$(Size_Human "$DLIMIT")" "$(Size_Human "$ULIMIT")" "$INTERVAL" "${COLOUR_USED}$aREVERSE" "$(Size_Human $USED)" "${aREVERSEr}$cBWHT" "$(Size_Human $CAPLIMIT)" "$STATUS"$xERASEEOL

							[ $RESULT_PAGECNT -lt 21 ] && RESULT_PAGECNT=$((RESULT_PAGECNT+1))
							CURRENT_ROW=$RESULT_PAGECNT


							if [ "$CMDSCROLL" == "ScrollWIndow" ];then
								#-----------------Experimental fixed window scrolling
								if [ -n "$CMDSCROLLDEBUG" ];then
									echo -en $xCSRPOS								# Save current cursor position
									GotoXY 6 9
									echo -en "R="$RESULT_PAGECNT" C="$CURRENT_ROW" T="$TOP_ROW" S="$SCROLL" MARK='"${HIGHLIGHT_ROWS}"' P="${PREV_MARK}$xERASEEOL
									echo -en $xHOME
									echo -en $xPOSCSR								# Restore previous cursor position
								fi

								if [ $RESULT_PAGECNT -eq 21 ] || [ $SCROLL -le 99 ];then
									if [ $SCROLL -eq 99 ] && [ -n "$HIGHLIGHT_ROWS" ];then
										SCROLL=$(echo "$HIGHLIGHT_ROWS" | awk '{print $1}')
									fi
									if [ -n "$SCROLL" ];then
										if [ $SCROLL -ne 99 ] && [ $RESULT_PAGECNT -eq 21 ];then
											SCROLL=$((SCROLL-1))
											if [ $SCROLL -eq 0 ] && [ $TOP_ROW -lt 16 ];then		# Leave room to scroll 4 rows!
												TOP_ROW=$((TOP_ROW+1))
												Hold_Scroll_Line
												# If the next MARK = 1 then it must be adjacent?
												if [ -z "$HIGHLIGHT_ROWS" ];then
													SCROLL=99
													break
												else
													# Lock additional lines until SCROLL <> 1
													while true
														do
															SCROLL=$(echo "$HIGHLIGHT_ROWS" | awk '{print $1}')
															if [ -n "$SCROLL" ] && [ $SCROLL -eq 1 ];then
																TOP_ROW=$((TOP_ROW+1))
																Hold_Scroll_Line
															else
																SCROLL=99
																break
															fi
														done
												fi
											fi
										fi
									else
										SCROLL=99
									fi
								fi
								if [ $RESULT_PAGECNT -eq 21 ] ;then
									RESULT_PAGECNT=21
								fi
								#-------------------------------------------------------------------------------------------
							fi
							if [ -z "$CMDNOLOG" ];then
								SayT "$NOW $HOSTNAME $IP Rx=$(Size_Human "$DELTA_RECV") Tx=$(Size_Human "$DELTA_XMIT") Rx/Tx limits $(Size_Human "$DLIMIT") $(Size_Human "$ULIMIT") in ${INTERVAL} Secs; Used $(Size_Human "$USED") out of Capped Total: $(Size_Human $CAPLIMIT)"
							fi

							if [ -n "$CMDREPORT" ];then
								echo -e "\"$(echo "$NOW" | sed 's/(/\",\"/g; s/)/\",\"/g; s/ //')\",$HOSTNAME,$IP,\"$(Size_Human "$DELTA_RECV")\",\"$(Size_Human "$DELTA_XMIT")\",\"$(Size_Human "$DLIMIT")\",\"$(Size_Human "$ULIMIT")\",${INTERVAL},"\""$(Size_Human "$USED")\",\"$(Size_Human $CAPLIMIT)" >> $REPORT_CSV
							fi

							echo -en ${cRESET}$cBBLU

						done

					if [ -z "$MONITORED_DEVICES" ];then
						echo -e $cGRA"\t"$NOW" NO clients to monitor"$cRESET; SayT  "NO clients to monitor"
					fi

					if [ "$CMDSCROLL" == "ScrollWIndow" ];then
						[ "$CMDQOS" == "AllowQOS" ] && TYPE="qos" || TYPE="block"
						BAD_LIST=$(Show_status "$TYPE")
						[  -n "$(echo "$BAD_LIST" | grep -F "0 devices")" ] && COLOUR=$cGRE || COLOUR=$cBRED
						echo -en $xCSRPOS								# Save current cursor position
						GotoXY 32 9
						echo -en ${COLOUR}${aREVERSE}${BAD_LIST}${aREVERSEr}$xERASEEOL
						#echo -en $xHOME
						echo -en $xPOSCSR								# Restore previous cursor position
					fi

					# Run once ?
					[ "$CMDONCE" == "RunOnce" ] && return 0

					END=$(date +%s)
					ELAPSED_SECS=$((END-START+ELAPSED_SECS2))

					XINTERVAL=$INTERVAL
					if [ $INTERVAL -gt $ELAPSED_SECS ];then				# If runtime exceeds $INTERVAL then continue
						XINTERVAL=$((INTERVAL-ELAPSED_SECS))
						StatusLine $CMDNOANSII"NoFLASH" ${cBYEL}$aREVERSE"Monitoring Resuming in $(printf "%s" "$(Convert_SECS_to_HHMMSS $XINTERVAL)") seconds...."$aREVERSEr

						# Cosmetic... keep user advised of remaining Pause!
						I=0
						SLICE=10
						while [ $I -lt $((XINTERVAL-1)) ];do
							sleep 1
							I=$((I+1))
							if [ $((I % SLICE)) -eq 0 ] || [ $I -gt $((XINTERVAL-SLICE)) ];then		# Print msg every $SLICE secs except for the last $SLICE
								REMAIN=$((XINTERVAL-I))
								StatusLine $CMDNOANSII"NoFLASH" ${cBYEL}$aREVERSE"Monitoring Resuming in $(printf "%s" "$(Convert_SECS_to_HHMMSS $REMAIN)") seconds...."$aREVERSEr
							fi
					   done

					fi

					# Check the client for new/removed entries ?
					if [ "Refresh" == "Refresh" ];then				# v1.02 Check if new clients added by another instance of script!

						START=$(date +%s)							# Adjust the INTERVAL otherwise results look odd! ;-)

						eval exec "$FD>$LOCKFILE"
						#Say "Acquiring lock semaphore Monitor Stage2 '"$LOCKFILE"'"
						flock -x $FD
						#Say "Lock semaphore Monitor Stage2 acquired '"$LOCKFILE"'"

						StatusLine $CMDNOANSII"Update" ${cYBLU}$aBOLD"Refreshing list of devices to be Quota monitored....please wait!"

						NEW_HOSTNAME_CNT=0

						# Create the variables for each of the new devices to be Quota monitored
						for HOSTNAME in $(iptables --line -nvxL $TABLE_IN | grep -vE "Chain|pkts" | grep -v "Block" | awk '{print $(NF-1)}')
							do

								HOSTNAME=$(echo "$HOSTNAME" | sed 's/\s\+//')

								if [ -z "$(echo "$MONITORED_DEVICES" | grep "$HOSTNAME")" ];then

									MONITORED_DEVICES=$MONITORED_DEVICES" "$HOSTNAME

									VHOSTNAME=${HOSTNAME//-/}				# Can't have '-' in Variable names

									if [ "$CMDIGNOREDEVICEQUOTA" != "IgnoreDeviceQuota" ];then	# v1.04
										# Check specific Quota set for device					# v1.04
										if [ -f $FN_QUOTA_LIMITS ];then
											Parse "$(grep -iE "^$HOSTNAME" "$FN_QUOTA_LIMITS")" " " HNAME TXL RXL DATAL
											if [ -n "$HNAME" ] && [ -n "$TXL" ] && [ -n "$RXL" ];then
												eval "${VHOSTNAME}_TX_LIMIT=$(Convert_1024KMG $TXL)"
												eval "${VHOSTNAME}_RX_LIMIT=$(Convert_1024KMG $TXL)"
												eval "${VHOSTNAME}_DATA_LIMIT=$(Convert_1024KMG $DATAL)"
											fi
										fi
									fi

									eval "${VHOSTNAME}_IP=$(Convert_TO_IP ${HOSTNAME})"
									eval "${VHOSTNAME}_BYTES_RECV=$(Get_Current_Bytes $HOSTNAME $TABLE_IN)"		# Current bytes count from iptables
									eval "${VHOSTNAME}_BYTES_XMIT=$(Get_Current_Bytes $HOSTNAME $TABLE_OUT)"	# Current bytes count from iptables
									eval "${VHOSTNAME}_BLOCKED="												# Timestamp when it was blocked in Epoch seconds

									NEW_HOSTNAME_CNT=$((NEW_HOSTNAME_CNT+1))
								fi

							done

						flock -u $FD
						#Say "Lock semaphore Monitor Stage2 released '"$LOCKFILE"'"

						END=$(date +%s)
						ELAPSED_SECS2=$((END-START))

						MONITORED_DEVICES=$(echo "$MONITORED_DEVICES" | sed 's/^ //p')
						# Remove the true hostname and comment duplicate
						MONITORED_DEVICES=$(echo "$MONITORED_DEVICES" | awk '{for (i=1;i<=NF;i++) if (!a[$i]++) printf("%s%s",$i,FS)}')	# Remove duplicates
						HOST_CNT=$(echo "$MONITORED_DEVICES" | wc -w)

						StatusLine $CMDNOANSII"NoFLASH" ${cBGRE}${aBOLD}${aREVERSE}"Monitoring "$HOST_CNT" Clients.... "$aREVERSEr
					fi

				done
				;;
		add|del|unblock|unblockqos)

				local STATUS=0										# Assume OK

				eval exec "$FD>$LOCKFILE"
				#Say "Acquiring lock semaphore Monitor_Client() '"$LOCKFILE"'"
				flock -x $FD
				#Say "Lock semaphore Monitor_Client() acquired '"$LOCKFILE"'"

				local ACTION=$1
				shift

				LAN_IPS=$1

				for IP in $LAN_IPS
					do

						local HOSTNAME=$(Hostname_from_IP "$IP")
						local HOSTNAME=${HOSTNAME%%.*}						# Strip domain

						if [ -z "$HOSTNAME" ];then							# v1.03 'ip=auto' can return blank hostname  ???
							STATUS=1
							LAN_IPS=$IP										# Report bad boy
							break
						fi

						case $ACTION in
							unblock)
								POS=$(iptables --line -nvL "$TABLE_IN"  | grep -E "Block.*$HOSTNAME"  | awk '{print $1}')
								[ -n "$POS" ] && iptables -D $TABLE_IN $POS
								POS=$(iptables --line -nvL "$TABLE_OUT" | grep -E "Block.*$HOSTNAME"  | awk '{print $1}')
								[ -n "$POS" ] && iptables -D $TABLE_OUT $POS

								# Was the device actually Blocked?
								[ -z "$POS" ] && return 1

								VHOSTNAME=${HOSTNAME//-/}						# Can't have '-' in Variable names
								eval "${VHOSTNAME}_BLOCKED="					# Timestamp when it was blocked in Epoch seconds
								;;
							unblockqos)

								POS=$(iptables --line -t mangle -nvL POSTROUTING | grep -E -m 1 "BlockQoS.*$HOSTNAME"  | awk '{print $1}')
								[ -n "$POS" ] && iptables -t mangle -D POSTROUTING $POS
								POS=$(iptables --line -t mangle -nvL POSTROUTING | grep -E -m 1 "BlockQoS.*$HOSTNAME"  | awk '{print $1}')
								[ -n "$POS" ] && iptables -t mangle -D POSTROUTING $POS

								# Was the device actually Blocked?
								#[ -z "$POS" ] && return 1

								VHOSTNAME=${HOSTNAME//-/}						# Can't have '-' in Variable names
								eval "${VHOSTNAME}_BLOCKED="					# Timestamp when it was blocked in Epoch seconds
								;;
							del)
								iptables -D $TABLE_IN  -i        $WAN_IF -o br0 -d $IP -m comment --comment "$HOSTNAME" 2>/dev/null
								iptables -D $TABLE_OUT -i br0 -o $WAN_IF        -s $IP -m comment --comment "$HOSTNAME" 2>/dev/null
								iptables -D $TABLE_IN  -i        $WAN_IF -o br0 -d $IP -m comment --comment "Block $HOSTNAME" 2>/dev/null
								iptables -D $TABLE_OUT -i br0 -o $WAN_IF        -s $IP -m comment --comment "Block $HOSTNAME" 2>/dev/null

								# QOS throttle rules							# v1.03
								iptables --line -nvL POSTROUTING -t mangle -o eth0 -s $IP/32 -m mark --mark 0x40000000/0xc0000000 -j MARK --set-mark 0x403FFFFF -m comment --comment "BlockQoS $HOSTNAME" 2>/dev/null
								iptables --line -nvL POSTROUTING -t mangle -o br0  -d $IP/32 -m mark --mark 0x80000000/0xc0000000 -j MARK --set-mark 0x803FFFFF -m comment --comment "BlockQoS $HOSTNAME" 2>/dev/null
								;;
							add)
								iptables -C $TABLE_IN  -i        $WAN_IF -o br0 -d $IP -m comment --comment "$HOSTNAME" 2>/dev/null
								if [ $? -eq 1 ];then
									iptables -A $TABLE_IN  -i        $WAN_IF -o br0 -d $IP -m comment --comment "$HOSTNAME"
								else
									STATUS=1										# Device already exists
								fi
								iptables -C $TABLE_OUT -i br0 -o $WAN_IF        -s $IP -m comment --comment "$HOSTNAME" 2>/dev/null
								if [ $? -eq 1 ];then
									iptables -A $TABLE_OUT -i br0 -o $WAN_IF        -s $IP -m comment --comment "$HOSTNAME"
								else
									STATUS=1										# Device already exists
								fi
								;;
						esac

					done

				flock -u $FD
				#Say "Lock semaphore Monitor_Client() released '"$LOCKFILE"'"

				return $STATUS
				;;
	esac
}
Show_status() {

	local TYPE=
	if [ "$1" == "qos" ] || [ "$1" == "block" ] || [ "$1" == "all" ];then
		local TYPE=$1
		shift
	fi

	if [ "$1" == "verbose" ];then									# Verbose/dump mode
		echo -en $cBCYA
		iptables --line -nvL $TABLE_IN 2> /dev/null
		echo -e
		iptables --line -nvL $TABLE_OUT  2> /dev/null
		echo -e
		iptables --line -t mangle -nvL POSTROUTING 2> /dev/null

	fi

	if [ "$TYPE" == "all" ];then
		echo -e ${cRESET}${cBWHT}"\n\t"$VER "Quota/Rate Monitoring every $cBGRE"$INTERVAL"${cBWHT} secs (Quota Rx/Tx Limit $cBGRE"$(Size_Human "$DLIMIT")"$cBWHT/$cBGRE"$(Size_Human "$ULIMIT")"$cBWHT and Quota Data Usage Capped Limit is $cBGRE"$(Size_Human "$CAPLIMIT")$cbWHT")\n"

		echo -e $cBGRE"\t\t\tThere are" $(iptables --line -nvL $TABLE_IN 2> /dev/null | grep -v "Block" | grep -cE "^[0-9]") "devices monitored\n"
	fi

	if [ "$TYPE" == "block" ] || [ "$TYPE" == "all" ];then
		local BAD_CNT=$(iptables --line -nvL $TABLE_IN 2> /dev/null| grep -v "BlockQoS" | grep -c "Block")
		[ $BAD_CNT -gt 0 ] &&  { COLOUR=$cBRED; BAD_LIST="\t("$(iptables --line -nvL $TABLE_IN 2> /dev/null | grep  -v "BlockQoS" | grep "Block" | awk '{print $(NF-1)}')")"; }
		echo -e $COLOUR"\t\t\tThere are" $BAD_CNT "devices BLOCKED" $BAD_LIST
	fi

	if [ "$TYPE" == "qos" ] || [ "$TYPE" == "all" ];then
		BAD_LIST=
		local BAD_CNT=$(iptables --line -t mangle -nvL POSTROUTING 2> /dev/null | grep -c "BlockQoS")    # v1.03
		if [ $BAD_CNT -gt 0 ];then
			BAD_LIST=$(iptables --line -t mangle -nvL POSTROUTING 2> /dev/null | grep "BlockQoS" | awk '{print $(NF-4)}')
			BAD_LIST=$(echo "$BAD_LIST" | awk '{for (i=1;i<=NF;i++) if (!a[$i]++) printf("%s%s",$i,FS)}')	# Remove duplicates
			BAD_CNT=$(echo $BAD_LIST | wc -w)
			COLOUR=$cBRED
			if [ "$TYPE" == "all" ];then
				echo -e $COLOUR"\n\t\t\tThere are" $BAD_CNT "devices throttled by QoS"
				BAD_LIST=$(iptables --line -t mangle -nvL POSTROUTING 2> /dev/null | grep -E "$IP.*match 0\x8.*BlockQoS" | awk '{print $(NF-4)}')
				[ -n "$BAD_LIST" ] && echo -e $cBRED"\n\t\t\t\tDOWNLOAD (Rx):\t ("$(echo $BAD_LIST | tr ' ' ',')")"
				BAD_LIST=$(iptables --line -t mangle -nvL POSTROUTING 2> /dev/null | grep -E "$IP.*match 0\x4.*BlockQoS" | awk '{print $(NF-4)}')
				[ -n "$BAD_LIST" ] && echo -e $cBRED"\n\t\t\t\tUPLOAD   (Tx):\t ("$(echo $BAD_LIST | tr ' ' ',')")"
			else
				echo "QoS="$BAD_CNT" "$(echo "$BAD_LIST" | tr ' ' ',')
			fi
		else
			echo -e $COLOUR"\t\t\tThere are" $BAD_CNT "devices throttled by QoS" $BAD_LIST
		fi
	fi
}
sigquit()
{
   echo -e "\a\n\t\tSignal QUIT received........"$cRESET
}

sigint()
{
	echo -en $xCSRPOS								# Save current cursor position

	GotoXY "1" "1"

	echo -en $cRESET"\e[1;${SCREEN_SIZE_ROWS}r"$cRESET

	echo -en $xPOSCSR								# Restore previous cursor position

	echo -e $cBRED"\a\n\t\tSignal INT (Ctrl+C) received, Script Termination......"					# CTRL-C
	echo -e $cRESET
	exit 0
}
Main(){}

ANSIColours

MYROUTER=$(nvram get computer_name)

FIRMWARE=$(echo $(nvram get buildno) | awk 'BEGIN { FS = "." } {printf("%03d%02d",$1,$2)}')

# Need assistance ?
if [ "$1" == "-h" ] || [ "$1" == "help" ];then
	clear													# v1.08
	echo -e $cBWHT
	ShowHelp
	echo -e $cRESET
	exit 0
fi

trap 'sigquit' QUIT
trap 'sigint'  INT
#trap ':'       HUP      # ignore the specified signals

#Say "PID is" $$

TABLE_IN="MyQUOTAi"		# Inbound
TABLE_OUT="MyQUOTAo"	# OutBound

INTERVAL=60					# Default 60 secs

BASE_DLIMIT=52428800		# Default Rx (Download) limit Bytes i.e 50MB
BASE_ULIMIT=10485760		# Default Tx (Upload)   limit Bytes i.e 10MB
BASE_CAPLIMIT=53687091200	# Default Data (Rx+Tx)  limit           50GB

#DLIMIT=5242880				# Current Device Rx (Download) limit Bytes i.e 5MB
DLIMIT=52428800				# Current Device Rx (Download) limit Bytes i.e 50MB
ULIMIT=10485760				# Current Device Tx (Upload)   limit Bytes i.e 10MB
CAPLIMIT=53687091200		# Current Device Data (Rx+Tx)  limit           50GB

LOCKFILE="/tmp/$(basename $0)-flock"
FD=188					# Unique File descriptor for $LOCKFILE

if [ -z "$1" ] || [ "$1" == "status" ] || [ "$1" == "verbose" ];then
	VERBOSE=
	[ "$2" == "verbose" -o "$1" == "verbose" ] && VERBOSE="verbose"
	Show_status "all" $VERBOSE
	echo -e $cRESET
	exit 0
fi

echo -e "\n"${cRESET}${cBWHT} $VER" Quota Monitoring....."

ROWS=30										# Default screen rows for 'scroll=' option
SCREEN_SIZE_ROWS=33
TOPROW=10									# Dynamic top row of 'scroll=' window

FN_QUOTA_LIMITS="/jffs/configs/QuotaLimits"	# Individual device Quota limits
CMDNOLOG=									# Default write Syslog records
CMDIPREMOVE=
CMDIPUNBLOCK=
ENFORCE_QUOTA_METRIC="Rx,Tx,Used"			# Apply Quota limits to ALL metrics
ACTION_RX=									# Action script for Rx Quota exceeded rather than default BLOCK action
ACTION_TX=									# Action script for Tx Quota exceeded rather than default BLOCK action
ACTION_USED=								# Action script for Total Data Used Quota exceeded rather than default BLOCK action
ALLOW_QOS=									# QOS throttling rules to be applied rather than a Total BLOCK

IP_CNT=0
OPTTXT=

WAN_IF=$(Get_WAN_IF_Name)

while [ $# -gt 0 ]; do    # Until you run out of parameters . . .
	case $1 in
		init|initqos)
					if [ "$1" == "initqos" ];then
						ALLOW_QOS="AllowQOS"
						QOSTXT=$aREVERSE"with QOS"$aREVERSEr
					fi
					Setup $1
					echo -e ${cRESET}${cBGRE}"\n\tQuota Monitoring" $QOSTXT "Setup complete.\n"$cRESET
					Show_status
					;;
		reset|resetdel)
						if [ "$1" == "reset" ];then
							Setup
							echo -e ${cRESET}${cBGRE}"\n\tQuota Monitoring Quota/Rate RESET complete.\n"$cRESET
							Show_status
						else
							if [ $(Chain_exists "$TABLE_IN") == "Y" ];then
								Setup "del"
								echo -e ${cRESET}${cBGRE}"\n\tQuota Monitoring Quota/Rate"${cBRED}$aBLINK "DELETED\n"$cRESET
							else
									echo -e $cBRED"\n\tQuota Monitoring does not exist.\n"$cRESET

							fi
						fi

					exit 0
					;;
		remove)												# v1.02 renamed - was 'flush'
					if [ $IP_CNT -eq 0 ];then
						echo -e $cBRED"\a\n\t***ERROR Missing 'ip=' arg as 'remove' is only valid in this context 'ip=    remove'\n"$cRESET
						exit 99
					fi
					CMDIPREMOVE="IPRemove"
					;;
		unblock|unblockqos)
					if [ $IP_CNT -eq 0 ];then
						echo -e $cBRED"\a\n\t***ERROR Missing 'ip=' arg as 'unblock' is only valid in this context 'ip=    unblock'\n"$cRESET
						exit 99
					fi
					[ "$1" == "unblock" ] && CMDIPUNBLOCK="IPUnBlock" || CMDIPUNBLOCK="IPUnBlockQOS"
					;;
		ignorezero)
					CMDIGNOREZERO="IgnoreZERO"
					[ -z "$OPTTXT" ] && OPTTXT="Filter: Only ACTIVE Clients displayed (IN+OUT > 0);" || OPTTXT=$OPTTXT"Only ACTIVE Clients displayed (IN+OUT > 0);"
					;;
		zero)
					CMDZERO="Zero"
					if [ $(Chain_exists "$TABLE_IN") == "Y" ] || [ $(Chain_exists "$TABLE_IN") == "Y" ];then
						iptables -Z $TABLE_IN 2>/dev/null
						iptables -Z $TABLE_OUT 2>/dev/null
						echo -e ${cRESET}${cBGRE}"\n\tQuota Monitoring Quota/Rate Counters zeroised .\n"$cRESET
						Show_status
						exit 0
					else
						echo -e $cBRED"\n\tQuota Monitoring does not exist.\n"$cRESET
						exit 95
					fi
					;;
		ip=*)
					if [ $(Chain_exists "$TABLE_IN") == "N" ];then
						echo -e $cBRED"\n\tQuota Monitoring does not exist. Please run 'init'\n"$cRESET
						exit 99
					else
						CMDIP=$(echo "$1" | sed -n "s/^.*ip=//p" | awk '{print $1}' | tr ',' ' ')

						if [ "$CMDIP" == "auto" ];then							# v1.03
							IP_GROUP_LIST=$(ip neigh show | grep br0 | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | cut -d' ' -f1)
							CMDIP=$1
						else
							if [ "$CMDIP" == "all" ];then
								CMDIP=$1
								shift
								case "$1" in
									unblock)
										IP_GROUP_LIST=$(iptables --line -nvL $TABLE_IN 2> /dev/null | grep  -v "BlockQoS" | grep "Block" | awk '{print $(NF-1)}')
										CMDIPUNBLOCK="IPUnBlock"
										;;
									unblockqos)
										IP_GROUP_LIST=$(iptables --line -t mangle -nvL POSTROUTING 2> /dev/null | grep -E "$IP.*match 0\x8.*BlockQoS" | awk '{print $(NF-4)}')
										IP_GROUP_LIST=${IP_GROUP_LIST}" "$(iptables --line -t mangle -nvL POSTROUTING 2> /dev/null | grep -E "$IP.*match 0\x4.*BlockQoS" | awk '{print $(NF-4)}')
										IP_GROUP_LIST=$(echo "$IP_GROUP_LIST" | awk '{for (i=1;i<=NF;i++) if (!a[$i]++) printf("%s%s",$i,FS)}')	# Remove duplicates
										CMDIPUNBLOCK="IPUnBlockQOS"
										;;
									*)
										echo -e $cBRED"\a\n\t***ERROR 'ip=all' requires 'unblock' or 'unblockqos'\n"$cRESET
										exit 94
										;;
								esac
							else
								IP_GROUP_LIST=$CMDIP
							fi
						fi

						GROUP_FOUND=0

						while true;do										# Iterate to expand any Groups within a Group
							for ITEM in $IP_GROUP_LIST
								do
									if [ -z "$(echo "$ITEM" | Is_Private_IPv4 )" ];then
										# Check for group names, and expand as necessary
										#	e.g. '192.168.1.30,192.168.1.50-192.168.1.54' -> '192.168.1.30 192.168.1.50 192.168.1.51 192.168.1.52 192.168.1.53 192.168.1.54'
										if [ -f "/jffs/configs/IPGroups" ];then		# '/jffs/configs/IPGroups' two columns
																					# ID xxx.xxx.xxx.xxx[[,xxx.xxx.xxx.xxx][-xxx.xxx.xxx.xxx]
											GROUP_IP=$(grep -iwE -m 1 "^$ITEM" /jffs/configs/IPGroups | awk '{$1=""; print $0}')
											if [ -n "$GROUP_IP" ];then
												GROUP_FOUND=1
												# Expand the list of IPs as necessary
												#	e.g. '192.168.1.30,192.168.1.50-192.168.1.54' -> '192.168.1.30 192.168.1.50 192.168.1.51 192.168.1.52 192.168.1.53 192.168.1.54'
												GROUP_IP=$(echo $GROUP_IP | tr ',' ' ')			# CSVs ?
												GROUP_IP=$(echo $GROUP_IP | tr ':' '-')			# Alternative range spec xxx.xxx.xxx.xxx:xxx.xxx.xxx.xxx
											else
												# Perform lookup
												GROUP_IP=$(nslookup "$ITEM" | grep -woE '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk 'NR>2')
												if [ -z "$GROUP_IP" ];then
													echo -e $cBRED"\a\n\t\t***ERROR Hostname '$1' INVALID\n"$cRESET
													exit 99
												fi
											fi
										else
											GROUP_IP=$ITEM
										fi

										# Expand any ranges - allow Hostnames e.g. LIFX-Table_light to pass through
										if [ -n "$(echo "$GROUP_IP" | grep "-")" ];then		# xxx-yyy range ?
											GROUP_IP="$(ExpandIPRange "$GROUP_IP")"
											RC=$?													# Should really check
										fi
										[ -n "$GROUP_IP" ] && LAN_IPS=$LAN_IPS" "$GROUP_IP
									else
										LAN_IPS=$LAN_IPS" "$ITEM
									fi
								done

								if [ $GROUP_FOUND -eq 0 ];then
									break
								fi

								IP_GROUP_LIST=$LAN_IPS			# Keep expanding
								LAN_IPS=
								GROUP_FOUND=0
						done

						LAN_IPS=$(echo "$LAN_IPS" | sed 's/^ //p')
						LAN_IPS=$(echo "$LAN_IPS" | awk '{for (i=1;i<=NF;i++) if (!a[$i]++) printf("%s%s",$i,FS)}')	# Remove duplicates
						IP_CNT=$(echo "$LAN_IPS" | wc -w)

					fi
					;;
		monitor)	CMDMONITOR="StartMonitor"			# Delay starting it until all params checked
					;;
		scroll=*)
					CMDSCROLL=$(echo "$1" | sed -n "s/^.*scroll=//p" | awk '{print $1}')
					if [ -n "$CMDSCROLL" ];then
						if [ -n "$(echo "$CMDSCROLL" | grep -F "?")" ];then
							CMDSCROLLDEBUG="ScrollDEBUG"
							CMDSCROLL=$(echo "$CMDSCROLL" | tr -d '?')
						else
							if [ -n "$(echo "$CMDSCROLL" | grep -E "^[0-9]+$")" ] && [ $CMDSCROLL -ge 1 ] && [ $CMDSCROLL -le 33 ];then
								ROWS=$CMDSCROLL
								CMDSCROLL="ScrollWIndow"
							else
								echo -e $cBRED"\a\n\t***ERROR '$1' must be numeric range 1-33\n"$cRESET
								exit 99
							fi
						fi
					fi
					CMDSCROLL="ScrollWIndow"			# v1.04 Use default scroll window 10-33
					[ -z "$OPTTXT" ] && OPTTXT="Scroll window ROWS=$ROWS;" || OPTTXT=$OPTTXT"Scroll window ROWS=$ROWS;"
					COLS=80
					;;
		qos)		CMDQOS="AllowQOS"					# v1.03
					if [ -n "$(tc filter show dev br0 | grep "flowid 1:100")" ];then
						ALLOW_QOS=$CMDQOS
						[ -z "$OPTTXT" ] && OPTTXT="QoS throttling;" || OPTTXT=$OPTTXT"QoS throttling;"
					else
						echo -e $cBRED"\a\n\t***ERROR Quota QoS rules 'classid/flowid 1:100' NOT defined (tc filter show dev br0)\n"$cRESET
						exit 99
					fi
					;;
		nolog)		CMDNOLOG="NoSyslog"					# Don't write Syslog messages (replicate screen records to Syslog)
					[ -z "$OPTTXT" ] && OPTTXT="No Syslog records will be written;" || OPTTXT=$OPTTXT"No Syslog records will be written;"
					;;
		once)		CMDONCE="RunOnce"
					[ -z "$OPTTXT" ] && OPTTXT="Run the report once;" || OPTTXT=$OPTTXT"Run the report once;"
					;;
		interval=*)	CMDINTERVAL=$(echo "$1" | sed -n "s/^.*interval=//p" | awk '{print $1}' | tr ',' ' ')
					if [ -n "$(echo "$CMDINTERVAL" | grep -E "^[0-9]+$")" ] && [ $CMDINTERVAL -ge 10 ];then
						INTERVAL=$CMDINTERVAL
					else
						echo -e $cBRED"\a\n\t***ERROR '$1' must be numeric and a minimum of 10 seconds\n"$cRESET
						exit 99
					fi
					;;
		dlimit=*)	CMDDLIMIT=$(echo "$1" | sed -n "s/^.*dlimit=//p" | awk '{print $1}' | tr ',' ' ' | tr 'a-z' 'A-Z')

					if [ -z "$(echo "$CMDDLIMIT" | tr -dc '0-9')" ] || [ "$(echo "$CMDDLIMIT" | tr -dc '0-9')" -eq 0 ];then
						echo -e $cBRED"\a\n\t***ERROR DOWNLOAD (Rx) Limit '$1' cannot be 0/NULL\n"$cRESET
						exit 99
					else
						BASE_DLIMIT=$(Convert_1024KMG "$CMDDLIMIT")
						CMDIGNOREDEVICEQUOTA="IgnoreDeviceQuota"	# v1.04 Override individual device Quota '/jff/config/Quota'
					fi

					;;
		ulimit=*)	CMDULIMIT=$(echo "$1" | sed -n "s/^.*ulimit=//p" | awk '{print $1}' | tr ',' ' ' | tr 'a-z' 'A-Z')
					if [ -z "$(echo "$CMDULIMIT" | tr -dc '0-9')" ] || [ "$(echo "$CMDULIMIT" | tr -dc '0-9')" -eq 0 ];then
						echo -e $cBRED"\a\n\t***ERROR UPLOAD (Tx) Limit '$1' cannot be 0/NULL\n"$cRESET
						exit 99
					else
						BASE_ULIMIT=$(Convert_1024KMG "$CMDULIMIT")
						CMDIGNOREDEVICEQUOTA="IgnoreDeviceQuota"	# v1.04 Override individual device Quota '/jff/config/Quota'
					fi
					;;
		cap=*)		CMDCAPLIMIT=$(echo "$1" | sed -n "s/^.*cap=//p" | awk '{print $1}' | tr ',' ' ' | tr 'a-z' 'A-Z')
					BASE_CAPLIMIT=$(Convert_1024KMG "$CMDCAPLIMIT")
					CMDIGNOREDEVICEQUOTA="IgnoreDeviceQuota"		# v1.04 Override individual device Quota '/jff/config/Quota'
					;;
		noansii)
					CMDNOANSII="NoANSII"
					;;
		quota=*)										# v1.02
					# Tx,Rx,Used
					CMDQUOTA=$(echo "$1" | sed -n "s/^.*quota=//p" | awk '{print $1}' | tr ',' ' ' | tr 'A-Z' 'a-z')

					ENFORCE_QUOTA_METRIC=

					for XMETRIC in $CMDQUOTA
						do
							# Change input format to only capitalise the first char e.g. 'rx' or 'rX' --> 'Rx'
							METRIC=$(echo $XMETRIC | awk '{print toupper(substr($0,0,1))tolower(substr($0,2))}')
							case XMETRIC in
								Rx|Tx|Used|"")
									[ -z "$ENFORCE_QUOTA_METRIC" ] && ENFORCE_QUOTA_METRIC=$METRIC || ENFORCE_QUOTA_METRIC=$ENFORCE_QUOTA_METRIC","$METRIC
										[ -z "$OPTTXT" ] && OPTTXT="Quota Metrics "$ENFORCE_QUOTA_METRIC" will be ENFORCED;" || OPTTXT=$OPTTXT"Quota Metrics "$ENFORCE_QUOTA_METRIC" will be ENFORCED;"
									;;
								*)
									echo -e $cBRED"\a\n\t***ERROR unrecognised  '"$XMETRIC"'\n"$cRESET
									exit 99
									;;
							esac
						done
					if [  -z "$ENFORCE_QUOTA_METRIC" ];then
						[ -z "$OPTTXT" ] && OPTTXT="Quota Metrics (Rx/Tx/Total Used) will NOT be enforced;" || OPTTXT=$OPTTXT"Quota Metrics will NOT be enforced;"
					fi
					;;
		actionrx=*)															#v1.02
					CMDACTIONRX=$(echo "$1" | sed -n "s/^.*actionrx=//p" | awk '{print $1}')
					# Check if valid external action script
					if [ -f "$CMDACTIONRX" ];then
						ACTION_RX=$CMDACTIONRX
						[ -z "$OPTTXT" ] && OPTTXT="Quota Rx Exceeded ACTION will use script '"$ACTION_RX"';" || OPTTXT=$OPTTXT"Quota Rx Exceeded ACTION will use script '"$ACTION_RX"';"
					else
						echo -e $cBRED"\a\n\t***ERROR Quota action script '"$1"' NOT found\n"$cRESET
						exit 99
					fi
					;;
		actiontx=*)															#v1.02
					CMDACTIONTX=$(echo "$1" | sed -n "s/^.*actiontx=//p" | awk '{print $1}')
					# Check if valid external action script
					if [ -f "$CMDACTIONTX" ];then
						ACTION_TX=$CMDACTIONTX
						[ -z "$OPTTXT" ] && OPTTXT="Quota Tx exceeded action will use script '"$ACTION_TX"';" || OPTTXT=$OPTTXT"Quota Tx exceeded action will use script '"$ACTION_TX"';"
					else
						echo -e $cBRED"\a\n\t***ERROR Quota action script '"$1"' NOT found\n"$cRESET
						exit 99
					fi
					;;
		actionused=*)															#v1.02
					CMDACTIONUSED=$(echo "$1" | sed -n "s/^.*actionused=//p" | awk '{print $1}')
					# Check if valid external action script
					if [ -f "$CMDACTIONUSED" ];then
						ACTION_USED=$CMDACTIONUSED
						[ -z "$OPTTXT" ] && OPTTXT="Quota Used exceeded action will use script '"$ACTION_USED "';" || OPTTXT=$OPTTXT"Quota Used exceeded action will use script '"$ACTION_USED"';"
					else
						echo -e $cBRED"\a\n\t***ERROR Quota action script '"$1"' NOT found\n"$cRESET
						exit 99
					fi
					;;
		report=*)
					REPORT_CSV=$(echo "$1" | sed -n "s/^.*report=//p" | awk '{print $1}')
					CMDREPORT="CreateCSV"
					[ -z "$OPTTXT" ] && OPTTXT="Quota Report: '$REPORT_CSV'" || OPTTXT=$OPTTXT"Quota Report: '$REPORT_CSV'"
					;;
		*)
			echo -e $cBRED"\a\n\t***ERROR unrecognised directive '"$1"'\n"$cRESET
			exit 99
			;;
	esac

	shift

done


# Off we go......
if [ -n "$CMDIP" ] && [ -n "$LAN_IPS" ];then
	if [ "$CMDIPREMOVE" == "IPRemove" ];then
		Monitor_Client "del" "$LAN_IPS"
		echo -e ${cRESET}${cBGRE}"\n\tQuota Monitoring clients:" $CMDIP "("$LAN_IPS") "${cBRED}$aREVERSE"Removed\n"$cRESET
	else
		if [ "$CMDIPUNBLOCK" == "IPUnBlock" ] || [ "$CMDIPUNBLOCK" == "IPUnBlockQOS" ] ;then
			if [ "$CMDIPUNBLOCK" == "IPUnBlock" ];then
				Monitor_Client "unblock" "$LAN_IPS"
			else
				Monitor_Client "unblockqos" "$LAN_IPS"
			fi

			if [ $? -eq 0 ];then
				echo -e ${cRESET}${cBGRE}"\n\tQuota Monitoring clients:" $CMDIP "("$LAN_IPS") "${cBGRE}$aREVERSE"UnBLOCKED\n"$cRESET
			else
				echo -e $cBRED"\a\n\t***ERROR '$CMDIP' not Blocked?\n"$cRESET
			fi
		else
			Monitor_Client "add" "$LAN_IPS"
			if [ $? -eq 0 ];then
				echo -e ${cRESET}${cBGRE}"\n\tQuota Monitoring clients:" $CMDIP "("$LAN_IPS") "${cBGRE}$aREVERSE"Added\n"$cRESET
			else
				echo -e $cBRED"\a\n\t***ERROR '"$CMDIP"' already in monitor list or ("$LAN_IPS") invalid?\n"$cRESET
			fi
		fi
	fi
	Show_status
fi

# Hopefully 'init ip=' has been processed...?
if [ $(Chain_exists "$TABLE_IN") == "Y" ];then
	if [ -n "$CMDMONITOR" ];then						# Auto-monitor or ONLY explicitly requested?
		clear
		echo -e ${cRESET}${cBWHT}						# Reserved for status line
		echo -en $xCSRPOS								# Save current cursor position
		GotoXY "6" "9"									# Reserved for 'scroll=?' debugging
		echo -en $xERASEEOL
		echo -en $xHOME
		echo -en $xPOSCSR
		SayT $VER" Quota Monitoring....."
		Monitor_Client "monitor"
	fi
else
	echo -e $cBRED"\a\n\t***ERROR Quota Monitoring iptables do not EXIST. Please use 'init/initqos'"$cRESET
fi

#StatusLine $CMDNOANSII"Clear"

echo -e $cRESET


exit 0
