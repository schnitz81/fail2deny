#!/bin/bash
set -x

PAST_TIME_LIMIT=$((60*20))  # past time in seconds to disallow failed logins
MAX_NO_OF_FAILS=11   # more fail logins than this will result in an IP ban
BANTIME=$((60*20))

LIST_FILE="/etc/fail2deny.list"
EVENT_LOG="/var/log/fail2deny.log"

FAILSTRINGS="-i -e fail -e invalid[[:space:]]user"  # Search words (case insensitive). The strings in log that are considered fail attempts.
ALLOWSTRINGS="-v -i -e check -e pam_unix -e '127.0.0.1'"           # Exceptions strings that will override the search words.

IPTABLES_CMD=$(which iptables)


############################### FUNCTIONS ##########################################


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
	while IFS= read -r line; do

		local epochNow=$(date +"%s")
		local expiredBanTime=$((epochNow-BANTIME))
		local listEpoch=$(echo "$line" | xargs | cut -d ' ' -f 1)
		local listIp=$(echo "$line" | xargs | cut -d ' ' -f 2)
		local iptablesIpOccurance=0

		if ! [[ $listIp =~ [0-9] ]]; then  # skip rest if line doesn't contain any digits
			continue
		fi
		# unban expired records
		if [[ $listEpoch -le $expiredBanTime ]]; then
			remove_ip "$listIp"  # remove line from list file
			$IPTABLES_CMD -D INPUT -s "$listIp" -j DROP  # unban IP from iptables

		# ban new records
		elif [[ $listEpoch -gt $expiredBanTime ]]; then
			# check if IP is already banned by analyzing iptables output
			mapfile iptablesOutput < <($IPTABLES_CMD -L INPUT -v -n)  # get iptables output
			if echo "${iptablesOutput[@]}" | fgrep -w "$listIp"; then  # check for IP in iptables output
				iptablesIpOccurance=1  # occurence is true
			fi
			if [[ $iptablesIpOccurance -lt 1 ]]; then  # if IP doesn't occur in iptables
				$IPTABLES_CMD -A INPUT -s "$listIp" -j DROP  # ban ip
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
	if ! grep -q $ipToBan $LIST_FILE; then
		echo "$epochNow $ipToBan" >> $LIST_FILE
		echo "$ipToBan added to ban list."

	else
		echo "$ipToBan already in ban list."
	fi
}


####################################################################################


# run as root
if [ $(whoami) != "root" ]; then
	echo "Please run as root"
	exit
fi

# check if inotify is installed
if [ -z "$(which inotifywait)" ] ; then
	echo "inotify not found. Please install inotify tools package."
	exit 1
fi

# check if iptables is installed and available
if [ -z "$IPTABLES_CMD" ]; then
	echo "iptables command not found! Make sure iptables is installed and available in the PATH."
fi

# check input parameter
if [ $# -lt 1 ]; then
	echo "Need one or more paths to log file."
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
	inotifywait -t $maxWaitTime -e modify -q "$file1" "$file2" "$file3" "$file4" "$file5" | while read file; do
		echo "--------------------------------------------------"
		echo -n "$(date +"%Y%m%d %H:%M:%S")  "  # put timestamp
		echo "Change in logfile detected. Analyzing log files..."

		for logfile in "$file1" "$file2" "$file3" "$file4" "$file5"; do

			# Skip loop iteration if file is dummy or empty
			if [ ! -f "$logfile" ] || ! [[ "$logfile" =~ [^a-zA-Z0-9\ ] ]]; then
				continue
			fi

			# Find last IP with failed login.
			echo "Checking $logfile..."
			ipToCheck=$(cat $logfile | grep $FAILSTRINGS | grep $ALLOWSTRINGS | grep -wo '[0-9]\+[.][0-9]\+[.][0-9]\+[.][0-9]\+' | tail -n 1)

			if [[ -n $ipToCheck ]]; then  # if not empty string

				echo
				echo -n "Checking if IP: $ipToCheck is banned..."
				if grep -wq $ipToCheck $LIST_FILE ; then  # do nothing more if IP is already banned
					echo "yes"
					continue
				else
					echo "no"
				fi

				echo
				echo -n "No of failed access attempts: "
				echo "$(grep -w $ipToCheck $logfile | grep $FAILSTRINGS | grep $ALLOWSTRINGS | wc -l)"  # print no of occurances
				echo
				if [ "$(grep -w $ipToCheck $logfile | grep $FAILSTRINGS | grep $ALLOWSTRINGS | wc -l)" -gt "$MAX_NO_OF_FAILS" ]; then  # check if no of occurances is more than allowed
					earliestOccurrenceWithinTimespan=$(cat $logfile | grep -we $ipToCheck | grep $FAILSTRINGS | grep $ALLOWSTRINGS | tr -s ' ' | cut -d ' ' -f 1 | tail -n $((MAX_NO_OF_FAILS+1)) | head -n 1)  # get earliest timestamp within timespan
					lastOccurrenceWithinTimespan=$(cat "$logfile" | grep -we $ipToCheck | grep $FAILSTRINGS | grep $ALLOWSTRINGS | tr -s ' ' | cut -d ' ' -f 1 | tail -n 1)  # get last timestamp
				else
					echo "Less than $((MAX_NO_OF_FAILS+1)) occurances. Will not ban."; continue  # break loop iteration
				fi
			else
				echo "No IP found to analyze."; continue  # break loop iteration
			fi

			epochLastOccurrenceWithinTimespan=$(date -d "${lastOccurrenceWithinTimespan}" +"%s")  # convert log timestamp to epoch
			epochPastLimit=$((epochLastOccurrenceWithinTimespan-PAST_TIME_LIMIT))  # calculate oldest relevant time for log timestamps
			epochEarliestOccurrenceWithinTimespan=$(date -d "${earliestOccurrenceWithinTimespan}" +"%s")  # convert log timestamp to epoch

			echo "          last epoch: $epochLastOccurrenceWithinTimespan ($lastOccurrenceWithinTimespan)"
			echo "oldest allowed epoch: $epochPastLimit ($PAST_TIME_LIMIT seconds diff)"
			echo " no $((MAX_NO_OF_FAILS+1)) past timestamp: $epochEarliestOccurrenceWithinTimespan ($earliestOccurrenceWithinTimespan)"
			echo

			# Check timespan and ban if less than 5 minutes.
			if [[ $epochEarliestOccurrenceWithinTimespan > $epochPastLimit ]]; then
				echo "Less than $PAST_TIME_LIMIT seconds between the $((MAX_NO_OF_FAILS+1)) latest fail logins. Will ban."
				echo
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

