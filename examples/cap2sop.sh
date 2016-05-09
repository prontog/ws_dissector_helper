#!/bin/bash

# Function to output usage information
usage() {
  cat <<EOF
Usage: ${0##*/} CAP_FILE 
Extract SOP message information from CAP_FILE.
EOF
  exit 1
}

if [[ ! -f $1 ]]; then
    usage
fi

CAP_FILE=$1

set -o errexit

tshark.exe -r $CAP_FILE -Y sop -Tfields -Eheader=n -Eseparator=";" \
           -e frame.number -e _ws.col.Time -e sop.msgtype -e sop.clientid \
		   -e eth.src -e eth.dst -e ip.src -e ip.dst | awk '
BEGIN { 
	FS = ";"
	OFS = ","
	# These are the msg types that contain the clientId field. All other msg
	# types will be discarded.
	msgTypesToPrint = "NO,OC,RJ"
	
	# Print header.
	print "frame", "dateTime", "msgType", "clientId", 
		  "ethSrc", "ethDst", "ipSrc", "ipDst"
}

{
	frame = $1
	dateTime = $2
	# Message types and clientIds are split into arrays.
	split($3, msgTypes, ",")
	split($4, clientIds, ",")
	ethSrc = $5
	ethDst = $6
	ipSrc = $7
	ipDst = $8
	
	# Keep only the messages that contain all
	fi = 0
	for(i in msgTypes) {
		#print i, msgTypes[i], clientIds[i]
		if (match(msgTypesToPrint, msgTypes[i])) {
			fi++
			filteredMsgTypes[fi] = msgTypes[i]			
		}
	}
	# Skill line if there was no messages to print.
	if (fi == 0) {
		next
	}
	
	if (length(filteredMsgTypes) != length(clientIds)) {
		printf("Skipping frame %d because of missing fields (%d, %d).", 
				frame, length(filteredMsgTypes), length(clientIds)) > "/dev/stderr"
		next
	}
	
	#print $0 > "/dev/stderr"
	for(i in filteredMsgTypes) {
		print frame, dateTime, filteredMsgTypes[i], clientIds[i], 
			  ethSrc, ethDst, ipSrc, ipDst
	}	
	delete filteredMsgTypes
}'
