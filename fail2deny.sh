#!/bin/bash
set -x

BANTIME=$((60*20))   # seconds long bantime
EVENT_LOG="/var/log/fail2deny.log"

PAST_TIME_LIMIT=$((60*20))  # past time in seconds to disallow failed logins
MAX_NO_OF_FAILS=11   # more fail occurances than this will result in an IP ban
LIST_FILE="/etc/fail2deny.list"


FAILSTRINGS="-i -e fail -e invalid[[:space:]]user"  # Search words (case insensitive). The strings in log that are considered fail attempts.
ALLOWSTRINGS="-v -i -e check -e pam_unix -e '127.0.0.1'"  # Exceptions strings that will override the search words.

# get firewall mgr path
if $(which iptables >/dev/null); then
	FWMGR_CMD=$(which iptables)
elif $(which nft >/dev/null); then
	FWMGR_CMD=$(which nft)
else
	echo "Error: No firewall manager found. nft or iptables needs to be in PATH."; exit 1
fi


############################### FUNCTIONS ##########################################


function dateparsing () {
	# Check what no of cols generates a valid date parsing and return the no. of cols
	if $(date -d "$(tail -n 1 $1 | tr -s ' ' | awk '{print $1, $2, $3, $4}')" +"%s" 1>/dev/null 2>&1); then
		echo "4"
	elif $(date -d "$(tail -n 1 $1 | tr -s ' ' | awk '{print $1, $2, $3}')" +"%s" 1>/dev/null 2>&1); then
		echo "3"
	elif $(date -d "$(tail -n 1 $1 | tr -s ' ' | awk '{print $1, $2}')" +"%s" 1>/dev/null 2>&1); then
		echo "2"
	elif $(date -d "$(tail -n 1 $1 | tr -s ' ' | awk '{print $1}')" +"%s" 1>/dev/null 2>&1); then
		echo "1"
	else
		echo "Error: Unable to parse date in log file $1"; exit 1
	fi
}


function get_max_wait_time () {
	local epochNow=$(date +"%s")
	local firstEpoch=$(grep -E '[0-9]' $LIST_FILE | xargs | cut -d ' ' -f 1 | head -n 1)
	if [[ $firstEpoch =~ [0-9] ]] && [[ $((firstEpoch+BANTIME)) -gt $epochNow ]]; then
		echo "$((firstEpoch+BANTIME-epochNow))"
	else
		echo "$BANTIME"
	fi
}


function ban_and_unban () {

	# set nftables set and rule
	if [[ "$FWMGR_CMD" =~ "nft" ]]; then

		# create set, can be run every time since same name sets aren't created
		$FWMGR_CMD add set ip filter fail2deny { type ipv4_addr\; }

		# add rule if missing
		if ! $(nft list ruleset | grep -q 'ip saddr @fail2deny drop'); then
			$FWMGR_CMD add rule ip filter INPUT ip saddr @fail2deny drop
		fi
	fi

	while IFS= read -r line; do

		local epochNow=$(date +"%s")
		local expiredBanTime=$((epochNow-BANTIME))
		local listEpoch=$(echo "$line" | xargs | cut -d ' ' -f 1)
		local listIp=$(echo "$line" | xargs | cut -d ' ' -f 2)
		local fwIpOccurrence=0

		if ! [[ $listIp =~ [0-9] ]]; then  # skip rest if line doesn't contain any digits
			continue
		fi
		# unban expired records
		if [[ $listEpoch -le $expiredBanTime ]]; then
			remove_ip "$listIp"  # remove line from list file
			if [[ "$FWMGR_CMD" =~ "nft" ]]; then  # unban command depending on fwmgr choice
				$FWMGR_CMD delete element ip filter fail2deny { $listIp }  # unban ip in nftables
			else
				$FWMGR_CMD -D INPUT -s "$listIp" -j DROP  # unban IP in iptables
			fi

		# ban new records
		elif [[ $listEpoch -gt $expiredBanTime ]]; then

			# check if IP is already banned by analyzing fwmgr output
			if [[ "$FWMGR_CMD" =~ "nft" ]]; then
				if nft list ruleset | awk '/fail2deny/{flag=1} flag; /}/{exit}' | grep -Fw "$listIp"; then  # check for IP in nftables output
					fwIpOccurrence=1  # occurence is true
				fi
			else
				mapfile iptablesOutput < <($FWMGR_CMD -L INPUT -v -n)  # get iptables output
				if echo "${iptablesOutput[@]}" | grep -Fw "$listIp"; then  # check for IP in iptables output
					fwIpOccurrence=1  # occurence is true
				fi
			fi
			if [[ $fwIpOccurrence -lt 1 ]]; then  # if IP doesn't occur in fwmgr
				if [[ "$FWMGR_CMD" =~ "nft" ]]; then
					$FWMGR_CMD add element ip filter fail2deny { $listIp }  # ban ip in nftables
				else
					$FWMGR_CMD -A INPUT -s "$listIp" -j DROP  # ban ip in iptables
				fi
				echo "********** $listIp banned **********"

				# log event
				echo -n "$(date +"%Y%m%d %H:%M:%S")  " >> $EVENT_LOG # put timestamp
				echo "$listIp banned" >> $EVENT_LOG
			else
				echo "IP already in iptables."
			fi
		fi
	done < $LIST_FILE
}


function remove_ip () {
	local ipToUnban=$1
	sed -i "/$ipToUnban/d" $LIST_FILE  # remove IP from list file
	echo "$listIp unbanned."

	# log event
	echo -n "$(date +"%Y%m%d %H:%M:%S")  " >> $EVENT_LOG # put timestamp
	echo "$listIp unbanned" >> $EVENT_LOG
}


function add_ip () {
	local ipToBan=$1
	local epochNow=$(date +"%s")
	if ! grep -q "$ipToBan" "$LIST_FILE"; then
		echo "$epochNow $ipToBan" >> $LIST_FILE
		echo "$ipToBan added to ban list."

	else
		echo "$ipToBan already in ban list."
	fi
}


####################################################################################


# run as root
if [ "$(whoami)" != "root" ]; then
	echo "Please run as root"
	exit
fi

# check if inotify is installed
if [ -z "$(which inotifywait)" ] ; then
	echo "inotify not found. Please install inotify tools package."
	exit 1
fi

# check input parameter
if [ $# -lt 1 ]; then
	echo "Need one or more paths to log file(s) to monitor."
	exit 1
fi

file1="$1"
file2="$2"
file3="$3"
file4="$4"
file5="$5"


touch $LIST_FILE  # make sure list file exists

echo -n "$(date +"%Y%m%d %H:%M:%S")  "  # put timestamp
echo "Starting to monitoring files..."

while true; do  # main loop
	maxWaitTime=$(get_max_wait_time)
	inotifywait -t "$maxWaitTime" -e modify -q "$file1" "$file2" "$file3" "$file4" "$file5" | while read file; do
		echo "--------------------------------------------------"
		echo -n "$(date +"%Y%m%d %H:%M:%S")  "  # put timestamp
		echo "Change in logfile detected. Analyzing log files..."

		for logfile in "$file1" "$file2" "$file3" "$file4" "$file5"; do

			# Skip loop iteration if file is dummy or empty
			if [ ! -f "$logfile" ] || ! [[ "$logfile" =~ [^a-zA-Z0-9\ ] ]]; then
				continue
			fi

			# figure out date parsing method
			noOfDateCols=$(dateparsing "$logfile")

			# Find last IP with failed login.
			echo "Checking $logfile..."
			ipToCheck=$(cat "$logfile" | grep $FAILSTRINGS | grep $ALLOWSTRINGS | grep -wo '[0-9]\+[.][0-9]\+[.][0-9]\+[.][0-9]\+' | tail -n 1)

			if [[ -n $ipToCheck ]]; then  # if not empty string

				if grep -wq "$ipToCheck" "$LIST_FILE"; then  # do nothing more if IP is already banned
					echo "$ipToCheck is already banned."; echo
					continue
				fi

				echo -n "No of failed access attempts: "
				echo "$(grep -w "$ipToCheck" "$logfile" | grep $FAILSTRINGS | grep $ALLOWSTRINGS | wc -l)"  # print no of occurrences
				echo
				if [ "$(grep -w "$ipToCheck" "$logfile" | grep $FAILSTRINGS | grep $ALLOWSTRINGS | wc -l)" -gt "$MAX_NO_OF_FAILS" ]; then  # check if no of occurrences is more than allowed
					earliestOccurrenceWithinOccurrenceLimit=$(grep -we "$ipToCheck" "$logfile" | grep $FAILSTRINGS | grep $ALLOWSTRINGS | tr -s ' ' | cut -d ' ' -f "$noOfDateCols" | tail -n $((MAX_NO_OF_FAILS+1)) | head -n 1)  # get earliest timestamp within occurrence span
					lastOccurrenceWithinOccurrenceLimit=$(grep -we "$ipToCheck" "$logfile" | grep $FAILSTRINGS | grep $ALLOWSTRINGS | tr -s ' ' | cut -d ' ' -f "$noOfDateCols" | tail -n 1)  # get last timestamp
				else
					echo "Less than $((MAX_NO_OF_FAILS+1)) occurrences. Will not ban."; echo
					continue  # break loop iteration
				fi
			else
				echo "No IP found to analyze."; continue  # break loop iteration
			fi

			epochNow=$(date +"%s")
			epochLastOccurrenceWithinOccurrenceLimit=$(date -d "${lastOccurrenceWithinOccurrenceLimit}" +"%s")  # convert log timestamp to epoch
			epochPastLimit=$((epochLastOccurrenceWithinOccurrenceLimit-PAST_TIME_LIMIT))  # calculate oldest relevant time for log timestamps
			epochEarliestOccurrenceWithinOccurrenceLimit=$(date -d "${earliestOccurrenceWithinOccurrenceLimit}" +"%s")  # convert log timestamp to epoch

			echo "          last epoch: $epochLastOccurrenceWithinOccurrenceLimit ($lastOccurrenceWithinOccurrenceLimit)"
			echo "oldest allowed epoch: $epochPastLimit ($PAST_TIME_LIMIT seconds diff)"
			echo " no $((MAX_NO_OF_FAILS+1)) past timestamp: $epochEarliestOccurrenceWithinOccurrenceLimit ($earliestOccurrenceWithinOccurrenceLimit)"; echo

			# don't ban if last occurrence is before past time limit
			if [[ $epochLastOccurrenceWithinOccurrenceLimit -lt $((epochNow-PAST_TIME_LIMIT)) ]]; then
				echo "Last abusive occurrence of $ipToCheck is longer ago than past time limit. Will not ban."; echo
				continue  # break loop iteration
			# ban if enough abusive occurrences within time span.
			elif [[ $epochEarliestOccurrenceWithinOccurrenceLimit -gt $epochPastLimit ]]; then
				echo "Less than $PAST_TIME_LIMIT seconds between the $((MAX_NO_OF_FAILS+1)) latest fail logins. Will ban."; echo
				echo "*** Banning IP: $ipToCheck ***"
				add_ip "$ipToCheck"
			else
				echo "More than $PAST_TIME_LIMIT seconds between fail logins. Not banning."
			fi
		done
	done
	# ban added IPs and unban expired IPs
	ban_and_unban
done
