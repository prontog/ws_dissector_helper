#!/bin/bash

# Function to output usage information
usage() {
  cat <<EOF
Usage: ${0##*/} [OPTION] CAP_FILE... 
Extract SOP message information from CAP_FILEs.

Options:
  -h	display this help text and exit
  -v	increase verbosity
EOF
  exit 1
}

# By default redirect tshark's STDERR to /dev/null.
TSHARK_STDERR='2>/dev/null'

while getopts "hv" option
do
	case $option in
		v) TSHARK_STDERR=;;
		\?) usage;;
	esac
done

shift $(( $OPTIND - 1 ))

if [[ $# -eq 0 ]]; then
	usage
fi

TSHARK_DISP_FILTER="-Y sop"
TSHARK_OUT_FIELDS="-e frame.number -e _ws.col.Time -e sop.msgtype -e sop.clientid -e eth.src -e eth.dst -e ip.src -e ip.dst"
TSHARK_CMD="tshark.exe $TSHARK_DISP_FILTER -Tfields -Eheader=n -Eseparator=';' $TSHARK_OUT_FIELDS"

# Print header.
echo frame,dateTime,msgType,clientId,ethSrc,ethDst,ipSrc,ipDst

until [[ -z $1 ]]
do
	if [[ ! -f $1 ]]; then
		echo $1 is not a file > /dev/stderr
	fi

	CAP_FILE=$1

	set -o errexit

	eval $TSHARK_CMD -r $CAP_FILE $TSHARK_STDERR | awk '
	BEGIN { 
		FS = ";"
		OFS = ","
		# These are the msg types that contain the clientId field. All other msg
		# types will be discarded.
		msgTypesToPrint = "NO,OC,RJ"
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
		
		# Keep only the messages that contain alluse 
		fi = 0
		for(i in msgTypes) {
			#print i, msgTypes[i], clientIds[i]
			if (match(msgTypesToPrint, msgTypes[i])) {
				fi++
				filteredMsgTypes[fi] = msgTypes[i]			
			}
		}
		# Skip line if there was no messages to print.
		if (fi == 0) {
			next
		}
		
		if (length(filteredMsgTypes) != length(clientIds)) {
			printf("Skipping frame %d because of missing fields (%d, %d).", 
					frame, length(filteredMsgTypes), length(clientIds)) > "/dev/stderr"
			next
		}
		
		for(i in filteredMsgTypes) {
			print frame, dateTime, filteredMsgTypes[i], clientIds[i], 
				  ethSrc, ethDst, ipSrc, ipDst
		}	
		delete filteredMsgTypes
	}'

	shift
done