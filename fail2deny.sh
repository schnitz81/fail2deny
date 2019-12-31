#!/bin/bash

DENYFILE='/etc/hosts.deny'

PAST_TIME_LIMIT=600  # past time in seconds to disallow failed logins
MAX_NO_OF_FAILS=4    # more fail logins than this will result in an IP ban

FAILSTRINGS='-i -e fail'                   # Search words (case insensitive). The strings in log that are considered fail attempts.
ALLOWSTRINGS='-v -i -e check -e pam_unix'  # Exceptions strings that will override the search words.

# check if inotify is installed
if [ -z "$(which inotifywait)" ] ; then
    echo "inotify not found. Please install inotify tools package."
    exit 1
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

echo -n "$(date +"%Y%m%d %H:%M:%S")  "  # put timestamp
echo "Starting to monitoring files..."

while true; do  # restart loop for inode release in case of logrotation
	inotifywait -t $PAST_TIME_LIMIT -e modify -q "$file1" "$file2" "$file3" "$file4" "$file5" | while read file; do
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
			ipToCheck=`cat $logfile | grep $FAILSTRINGS | grep $ALLOWSTRINGS | grep -wo '[0-9]\+[.][0-9]\+[.][0-9]\+[.][0-9]\+' | tail -n 1`

			if [[ ! -z $ipToCheck ]]; then  # if not empty string

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
				echo `grep -w $ipToCheck $logfile | grep $FAILSTRINGS | grep $ALLOWSTRINGS | wc -l`  # print no of occurances
				echo
				if [ `grep -w $ipToCheck $logfile | grep $FAILSTRINGS | grep $ALLOWSTRINGS | wc -l` -gt $MAX_NO_OF_FAILS ]; then  # check if no of occurances is more than allowed
					earliestOccurrenceWithinTimespan=`cat $logfile | grep -we $ipToCheck | grep $FAILSTRINGS | grep $ALLOWSTRINGS | cut -d ' ' -f -3 | tail -n $((MAX_NO_OF_FAILS+1)) | head -n 1`  # get earliest timestamp within timespan
					lastOccurrenceWithinTimespan=`cat $logfile | grep -we $ipToCheck | grep $FAILSTRINGS | grep $ALLOWSTRINGS | cut -d ' ' -f -3 | tail -n 1`  # get last timestamp
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
				echo "ALL: $ipToCheck" >> $DENYFILE
			else
				echo "More than $PAST_TIME_LIMIT seconds between fail logins. Not banning."
			fi
		done
	done
done
