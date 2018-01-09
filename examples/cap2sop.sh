#!/usr/bin/env bash

# Function to output usage information
usage() {
  cat <<EOF
Usage: ${0##*/} [OPTION] CAP_FILE...
Extract SOP message information from CAP_FILEs.

Options:
  -h	display this help text and exit
  -v	increase verbosity (stderr). A single -v will show critical, error, info
        and debug messages. Double -v will show trace messages as well. Note
        that double -v is VERY verbose. Use for troubleshooting a dissector.

Example:
  ${0##*/} -v sop.pcapng
EOF
  exit 1 >&2
}
# Print an error message
error() {
	echo "${0##*/}: $*" >&2
	exit 1
}
verbose_echo() {
    if [[ $verbosity_level -ge 1 ]]; then
	   echo ${0##*/}: $* >&2
    fi
}
# Increase verbosity level. Default is quiet (0).
verbosity_level=0
increase_verbosity() {
    verbosity_level=$((verbosity_level + 1))
}

while getopts "hv" option
do
	case $option in
		v) increase_verbosity;;
		\?) usage;;
	esac
done

# By default redirect tshark's STDERR to /dev/null.
TSHARK_STDERR='2>/dev/null'
SOP_TRACE=
if [[ $verbosity_level -ge 1 ]]; then
	TSHARK_STDERR=
fi
if [[ $verbosity_level -ge 2 ]]; then
	SOP_TRACE="-o sop.trace:TRUE"
fi

shift $(( $OPTIND - 1 ))

if [[ $# -eq 0 ]]; then
	usage
fi

TSHARK_DISP_FILTER="-Y sop"
TSHARK_OUT_FIELDS="-e frame.number -e _ws.col.Time -e sop.msgtype -e sop.clientid -e eth.src -e eth.dst -e ip.src -e ip.dst"
TSHARK_CMD="tshark $SOP_TRACE $TSHARK_DISP_FILTER -T fields -E header=n -E separator=',' -E aggregator=';' -o gui.column.format:'Time,%At' $TSHARK_OUT_FIELDS"

set -o errexit

# Print header.
echo frame,dateTime,msgType,clientId,ethSrc,ethDst,ipSrc,ipDst,capFile

until [[ -z $1 ]]
do
	if [[ ! -f $1 ]]; then
		echo $1 is not a file >&2
	fi

	CAP_FILE=$1

    verbose_echo "processing $CAP_FILE" >&2

    # Update SOP specs env vars with the appropriate values.
    . $SOP/specs/sop_specs_path.sh $CAP_FILE

	eval $TSHARK_CMD -r $CAP_FILE $TSHARK_STDERR | awk -v CAP_FILE="${CAP_FILE##*/}" '
	BEGIN {
		FS = ","
		OFS = ","
		# This was needed for Cygwin with "Windows" tshark.
		RS = "\r\n|\n"
		# These are the msg types that contain the clientId field. All other
		# message types will be discarded.
		msgTypesToPrint = "NO,OC,RJ"
	}

	{
		frame = $1
		dateTime = $2
		# Message types and clientIds are split into arrays.
		split($3, msgTypes, ";")
		split($4, clientIds, ";")
		ethSrc = $5
		ethDst = $6
		ipSrc = $7
		ipDst = $8

		# Copy the messages types that are included in msgTypesToPrint to
		# array filteredMsgTypes.
		fi = 0
		for(i in msgTypes) {
			if (match(msgTypesToPrint, msgTypes[i])) {
				fi++
				filteredMsgTypes[fi] = msgTypes[i]
			}
		}

		# Skip line if there was no messages to print.
		if (fi == 0) {
			next
		}

		# filteredMsgTypes should have the same length with clientIds.
		if (length(filteredMsgTypes) != length(clientIds)) {
			printf("Skipping frame %d because of missing fields (%d, %d).",
					frame, length(filteredMsgTypes), length(clientIds)) > "/dev/stderr"
			next
		}

		for(i in filteredMsgTypes) {
			print frame, dateTime, filteredMsgTypes[i], clientIds[i], ethSrc, ethDst,
				  ipSrc, ipDst, CAP_FILE
		}

		# Clean up array filteredMsgTypes before moving to the next line.
		delete filteredMsgTypes
	}'

	shift
done
