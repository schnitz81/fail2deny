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

denyfile='/etc/hosts.deny'

failstrings='-i -e fail'  # ******************** Search words (case insensitive). The strings in log that are considered fail attempts. 
allowstrings='-v -i -e check -e pam_unix'  # ************************** Exceptions strings that will override the search words.

echo -n "$(date +"%Y%m%d %H:%M:%S")  "  # Put timestamp
echo "Starting to monitoring files..."
# loop
inotifywait -m -e modify -q "$file1" "$file2" "$file3" "$file4" "$file5" | while read file
do
	echo "--------------------"
	echo -n "$(date +"%Y%m%d %H:%M:%S")  "  # Put timestamp
	echo "Change in logfile detected. Analyzing log files..."
	
	for logfile in "$file1" "$file2" "$file3" "$file4" "$file5"; do 

		# Skip loop iteration if file is dummy or empty
		if [ ! -f $logfile ] || ! [[ "$logfile" =~ [^a-zA-Z0-9\ ] ]]; then
			continue
		fi

		# Find last IP with failed login.
		echo "Checking $logfile..." 
		ipToCheck=`cat $logfile | grep $failstrings | grep $allowstrings | grep -o '[0-9]\+[.][0-9]\+[.][0-9]\+[.][0-9]\+' | tail -n 1`
	
		if [[ ! -z  $ipToCheck ]]; then  # if not empty string
			echo
			echo "IP number $ipToCheck has made one or more failed access attempts."
			echo
			echo -n "No of failed access attempts: "
			echo `grep $ipToCheck $logfile | grep $failstrings | grep $allowstrings | wc -l`   # Print no of occurances
			echo
			if [ `grep $ipToCheck $logfile | grep $failstrings | grep $allowstrings | wc -l` -gt 4 ]; then  # Check if no of occurances > 4
				fiveTimeStampsAgo=`cat $logfile | grep -e $ipToCheck $failstrings | grep $allowstrings | tail -n 5 | grep -o '[0-9]\{2\}\:[0-9]\{2\}' | head -n 1`  # Get fifth last time
			else
				echo "Less than five occurances. Will not ban."; echo "-------------------"; continue  # Break loop iteration.
			fi
		else 
			echo "No IP found to analyze."; echo "-------------------"; continue  # Break loop iteration.
		fi  
		
		NOW=$(date +"%T")
		_5MINSAGO=$(date --date="-5 minutes" +"%T")

		echo now:                  $NOW
		echo five mins ago:        $_5MINSAGO
		echo five time stamps ago: $fiveTimeStampsAgo
		echo 

		# Check timespan and ban if less than 5 minutes. 
		if [[ $fiveTimeStampsAgo > $_5MINSAGO ]]; then
			echo "Less than five minutes between the 5 latest fail logins. Will ban."
			echo "Checking for IP in deny file..." 
			if ! grep -q $ipToCheck $denyfile ; then
				echo "Banning IP..."
				echo "ALL: $ipToCheck" >> $denyfile
			else
				echo "IP already in deny file."
			fi
		else
			echo "More than five minutes between fail logins. Not banning."
		fi
		echo "--------------------"
	done 
done
