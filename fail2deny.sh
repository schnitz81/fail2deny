#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Need one or more paths to log file."
    exit 1
fi

file1="$1"
file2="$2"
file3="$3"
file4="$4"
file5="$5"

DENYFILE='/etc/hosts.deny'

PAST_TIME_LIMIT=600  # past time in seconds to disallow failed logins
MAX_NO_OF_FAILS=4    # more fail logins than this will result in an IP ban

failstrings='-i -e fail'                   # Search words (case insensitive). The strings in log that are considered fail attempts.
allowstrings='-v -i -e check -e pam_unix'  # Exceptions strings that will override the search words.

echo -n "$(date +"%Y%m%d %H:%M:%S")  "  # put timestamp
echo "Starting to monitoring files..."

inotifywait -m -e modify -q "$file1" "$file2" "$file3" "$file4" "$file5" | while read file
do
	echo "--------------------------------------------------"
	echo -n "$(date +"%Y%m%d %H:%M:%S")  "  # put timestamp
	echo "Change in logfile detected. Analyzing log files..."

	for logfile in "$file1" "$file2" "$file3" "$file4" "$file5"; do

		# Skip loop iteration if file is dummy or empty
		if [ ! -f $logfile ] || ! [[ "$logfile" =~ [^a-zA-Z0-9\ ] ]]; then
			continue
		fi

		# Find last IP with failed login.
		echo "Checking $logfile..."
		ipToCheck=`cat $logfile | grep $failstrings | grep $allowstrings | grep -wo '[0-9]\+[.][0-9]\+[.][0-9]\+[.][0-9]\+' | tail -n 1`

		if [[ ! -z $ipToCheck ]]; then  # if not empty string

			echo
			echo "IP: $ipToCheck has made one or more failed access attempts."
			echo
			echo -n "Checking if IP: $ipToCheck is banned..."
                        if grep -wq $ipToCheck $DENYFILE ; then  # do nothing more if IP is already banned
                                echo "yes"
				continue
			else
				echo "no"
                        fi

			echo
			echo -n "No of failed access attempts: "
			echo `grep -w $ipToCheck $logfile | grep $failstrings | grep $allowstrings | wc -l`  # print no of occurances
			echo
			if [ `grep -w $ipToCheck $logfile | grep $failstrings | grep $allowstrings | wc -l` -gt $MAX_NO_OF_FAILS ]; then  # check if no of occurances is more than allowed
				fiveTimestampsAgo=`cat $logfile | grep -we $ipToCheck | grep $failstrings | grep $allowstrings | cut -d ' ' -f -3 | tail -n $((MAX_NO_OF_FAILS+1)) | head -n 1`  # get fifth last time
			else
				echo "Less than five occurances. Will not ban."; continue  # break loop iteration
			fi
		else
			echo "No IP found to analyze."; continue  # break loop iteration
		fi

		epochNow=$(date +"%s")
		epochPastLimit=$((epochNow-PAST_TIME_LIMIT))
		epochFiveTimestampsAgo=$(date -d "${fiveTimestampsAgo}" +"%s")  # convert the log timestamp to epoch

		echo "                 now: $epochNow"
		echo "oldest allowed epoch: $epochPastLimit"
		echo "      no $((MAX_NO_OF_FAILS+1)) timestamp: $epochFiveTimestampsAgo ($fiveTimestampsAgo)"
		echo

		# Check timespan and ban if less than 5 minutes.
		if [[ $epochFiveTimestampsAgo > $epochPastLimit ]]; then
			echo "Less than $PAST_TIME_LIMIT seconds between the $((MAX_NO_OF_FAILS+1)) latest fail logins. Will ban."
			echo 
			echo "*** Banning IP: $ipToCheck ***"
			echo "ALL: $ipToCheck" >> $DENYFILE
		else
			echo "More than $PAST_TIME_LIMIT seconds between fail logins. Not banning."
		fi
	done
done
