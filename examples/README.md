Simple Order Protocol (sop). An imaginary protocol.
========

This is a simple, text protocol for an imaginary stock exchange. Use it to place simple orders and make simple trades.

All message types follow the format HEADER|PAYLOAD|TRAILER (note that '|' is not included in the protocol).

The HEADER is very simple:

Field | Length | Type | Description
-----|---------|------|------
SOH | 1 | STRING | Start of header.
LEN | 3 | NUMERIC |Length of the payload (i.e. no header/trailer).

The TRAILER is even simpler:

Field | Length | Type | Description
-----|---------|------|------
ETX | 1 | STRING | End of text.

The message types are:

Type | Description | Full Spec | Payload Spec
-----|-------------|-----------|--------------
NO | New Order | [NO_full.csv](NO_full.csv) | [NO.csv](NO.csv)
OC | Order Confirmation | [OC_full.csv](OC_full.csv) | [OC.csv](OC.csv)
TR | Trade | [TR_full.csv](TR_full.csv) | [TR.csv](TR_full.csv)
RJ | Rejection | [RJ_full.csv](RJ_full.csv) | [RJ.csv](RJ.csv)
EN | Exchange News | [EN_full.csv](EN_full.csv) | [EN.csv](EN.csv)
BO | Best Bid and Offer | [BO_full.csv](BO_full.csv) | [BO.csv](BO.csv)

The specs of each message can be found at the relevant CSV file. As you can see there are two CSV files per message type. One contains the full spec which includes header-payload-trailer and the other contains only the payload.

Dissector
------------

You will find two dissectors for SOP:

- [sop.lua](sop.lua) uses the payload CSV files and dynamically creates the header and trailer parts.
- [sop_alt.lua](sop_alt.lua) uses the full CSV files. There are no header and trailer COMPOSITE field. All fields are visualized in the same tree in the *Packet Details* pane.

Installation
------------

Add the following lines at the end of Wireshark's `init.lua` script:

``` lua
WSDH_SCRIPT_PATH='path to the directory src of the repo'
SOP_SPECS_PATH='path to the directory of the CSV specs'
dofile('path to sop.lua or sop_alt.lua')
```

Testing
-------

Tested on *Wireshark 2.0.1* and later versions.

At this point the tests are manual. In the *txt* files you will find messages of different type that can be used with a tool like *nc*.

1. Start a server with `nc -k -l 9001`
2. Start *tshark* with a display filter with the protocol name: `tshark -Y 'sop'`. Note that sometimes this approach might hide some Lua errors. Then you can repeat the test using `Wireshark` instead of `tshark`.
3. Connect with a client and send one or more messages from a file: `cat conversation.txt | while read line; do echo -n "$line"; sleep 1; done | nc SERVER_IP 9001`
4. If lines start appearing in the filtered *tshark* output then the test was successful.

If you finish testing, you can save the captured frame to a file for future tests.
