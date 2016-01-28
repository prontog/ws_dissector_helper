Simple Order Protocol (sop). An imaginary protocol.
========

This is a simple, text protocol for an imaginary stock exchange. With it you can place simple orders in order make trades.

All message types follow the format HEADER|PAYLOAD|TRAILER (note that '|' is not included in the protocol).

The HEADER is very simple:

Field | Length | Type | Description
-----|---------|------|------
SOH | 1 | STRING | Start of header.
LEN | 3 | STRING |Length of the payload (i.e. no header/trailer).

The TRAILER is even simpler:

Field | Length | Type | Description
-----|---------|------|------
ETX | 1 | STRING | End of text.

The message types are:

Type | Description | Spec
-----|-------------|-----
NO | New Order | [NO.csv](NO.csv)
OC | Order Confirmation | [OC.csv](OC.csv)
TR | Trade | [TR.csv](TR.csv)
RJ | Rejection | [RJ.csv](RJ.csv)
EN | Exchange News | [EN.csv](EN.csv)
BO | Best Bid and Offer | [BO.csv](BO.csv)

The specs of the payload of each message can be found at the relevant CSV file.

Dissector
------------

The code for the dissector at file [sop.lua](sop.lua)

Installation
------------

Add the following lines at the end of Wireshark's `init.lua` script:

``` lua
WSDH_SCRIPT_PATH="Replace this with the path to the directory src of the repo."
SOP_SPECS_PATH="Replace this with the path to the directory of the CSV specs."
dofile("Replace with full path to this file.")
```

Testing
-------

Tested on *Wireshark 2.0.1*.

At this point the tests are manual. In the *txt* files you will find messages of different type that can be used with a tool like *nc*.

1. Start a server with `nc -l 9001`
2. Start *tshark* with a display filter with the protocol name: `tshark -Y 'sop'`. Note that sometimes this approach might hide some Lua errors. Then you can repeat the test using `Wireshark` instead of `tshark`.
3. Connect with a client and send one or more messages from a file: `cat conversation | nc SERVER_IP 9001`
4. If lines start appearing in the filtered *tshark* output then the test was successful.

If you finish testing, you can save the captured frame to a file for future tests.
