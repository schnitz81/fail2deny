#!/bin/bash

file1='/var/log/auth.log'

# *********************************** In case of more log files, change the "/dev/null" dummies to file paths. 
file2='/dev/null'
file3='/dev/null'
file4='/dev/null'
file5='/dev/null'


denyfile='/tmp/hosts.deny'

failstrings='-e fail -e Invalid'  # ******************** Search words (case insensitive). The strings in log that are considered fail attempts. 

echo -n "$(date +"%Y%m%d %H:%M:%S")  "  # Put timestamp
echo "Starting to monitoring files..."
# loop
inotifywait -m -e modify -q $file1 $file2 $file3 $file4 $file5 | while read file
do
	echo -n "$(date +"%Y%m%d %H:%M:%S")  "  # Put timestamp
	echo "Change in logfile detected. Analyzing log files..."
	
	for logfile in $file1 $file2 $file3 $file4 $file5; do 

		# Skip loop iteration if file is dummy
		if [ ! -f $logfile ]; then
			continue
		fi

		# Find last IP with failed login.
		echo
		echo "Checking $logfile..." 
		ipToCheck=`cat $logfile | grep -i $failstrings | grep -o '[0-9]\+[.][0-9]\+[.][0-9]\+[.][0-9]\+' | tail -n 1`
	
		if [[ ! -z  $ipToCheck ]]; then  # if not empty string
			echo
			echo "IP number $ipToCheck has made one or more failed access attempts."
			echo
			echo -n "No of failed access attempts: "
			echo `grep -e $ipToCheck $logfile | grep $failstrings | wc -l`   # Print no of occurances
			echo
			if [ `grep -e $ipToCheck $logfile | grep $failstrings | wc -l` -gt 4 ]; then  # Check if no of occurances > 4
				earlyTime=`cat $logfile | grep -e $ipToCheck $failstrings | tail -n 5 | grep -o '.\{0,2\}\:.\{0,2\}' | head -n 1`  # Get fifth last time
				lateTime=`cat $logfile | grep -e $ipToCheck $failstrings | tail -n 1 | grep -o '.\{0,2\}\:.\{0,2\}' | head -n 1`  # Get last time
			else
				echo "Less than five occurances. Will not ban."; echo "-------------------"; continue  # Break loop iteration.
			fi
		else 
			echo "No IP found to analyze."; echo "-------------------"; continue  # Break loop iteration.
		fi  
		
		# Get minutes
		earlyMinTime=`date --date="$earlyTime" +%M`
		lateMinTime=`date --date="$lateTime" +%M`
		earlyHourTime=`date --date="$earlyTime" +%H`
		lateHourTime=`date --date="$lateTime" +%H`
		
		hDiff=$((10#$lateHourTime-10#$earlyHourTime))
		
		# Adjust for minute overflow.
		if [ $lateMinTime -lt 5 ] && [ $earlyMinTime -gt 54 ] && [ $hDiff -lt 2 ]; then
		        lateMinTime=$((lateMinTime+5))
		        earlyMinTime=$((earlyMinTime+5-60))
			hDiff=0
		fi
		mDiff=$((10#$lateMinTime-10#$earlyMinTime))
		
		echo Early minute: $earlyMinTime
		echo Last minute:  $lateMinTime
		echo Early hour:   $earlyHourTime
		echo Last hour:    $lateHourTime
		echo Minute diff:  $mDiff
		echo Hour diff:    $hDiff
		echo
		
		# Check timespan and ban if less than 5 minutes. 
		if [ $hDiff -lt 1 ] && [ $mDiff -lt 6 ]; then
			echo "Less than five minutes between fail logins. Will ban."
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
		echo "-------------------"
	done 
done
