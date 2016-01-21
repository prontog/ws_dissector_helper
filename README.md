ws_dissector_helper
========

Helper for creating a Wireshark Dissector in Lua. For text protocols only.

Basic features are:

- Messages specifications in CSV format.
- Fixed length fields:
	- STRING. This is the default type.
	- FIXED. These are strings with a fixed value.
	- NUMERIC.
- Variable length string fields.
- Composite fields. Fields that are comprised of other fixed length fields. Composite fields are visualized with a subtree in the *Packet Details* pane.
- Repeating groups. These are composite fields that are repeated. The number of repeats is taken by another field.
- Default settings:
	- ports. The ports to register.
	- trace. Useful for debugging purposes.
- Message header and trailer.
- All fields can be used in Wireshark's display filters.
- Simple and flexible. Simple, because you could make small changes to the example protocol and create your own. Flexible, because you can override pretty much all functionality or add your own.

Getting started
---------------

Create a lua script for our new dissector. Let's name it *sop.lua* since the dissector we will create will be for the SOP protocol (an imaginary protocol used in this example).

Add the following lines at the end of Wireshark's **init.lua** script:
``` lua
WSDH_SCRIPT_PATH="Replace this with the path to the directory src of the repo."
SOP_SPECS_PATH="Replace this with the path to the directory of the CSV specs."
dofile("Replace with full path to the sop.lua file")
```

Then in the **sop.lua** file:

Create a Proto object for your dissector. The Proto class is part of Wireshark's Lua API.
``` lua
sop = Proto('SOP', 'Simple Order Protocol')
```

Load the ws_dissector_helper script. We will use the `wsdh` object to access various helper functions.
``` lua
local wsdh = dofile(WSDH_SCRIPT_PATH .. "ws_dissector_helper.lua")
```

Create the proto helper. Note that we pass the Proto object to the `createProtoHelper` factory function.
``` lua
local protoHelper = wsdh.createProtoHelper(sop)
```

Create a table with the values for the default settings. These are:

- ports. The ports to register.
- trace. Useful for debugging purposes.

The values can be changed from the *Protocols* sections of  Wireshark's *Preferences* dialog.
``` lua
local defaultSettings = {
	ports = '7001-7010',
	trace = true
}
protoHelper:setDefaultPreference(defaultSettings)
```

Define the protocol's message types. Each message type has a *name* and *file* property. The file property is the filename of the CSV file that contains the specification of the fields for the message type. Note that the CSV files should be located in *SOP_SPECS_PATH*.
``` lua
local msg_types = { { name = 'NO', file = 'NO.csv' }, 
				    { name = 'OC', file = 'OC.csv' },
					{ name = 'TR', file = 'TR.csv' },
					{ name = 'RJ', file = 'RJ.csv' } }
```

Define fields for the header and trailer. If your CSV files contain all the message fields then there is no need to manually create fields for the header and trailer. In our example, the CSV files contain the specification of the payload of the message.
```lua
local SopFields = {
	SOH = wsdh.Field.FIXED(1,'sop.header.SOH', 'SOH', '\x01','Start of Header'),
	LEN = wsdh.Field.STRING(3,'sop.header.LEN', 'LEN','Length of the payload (i.e. no header/trailer)'),	
	ETX = wsdh.Field.FIXED(1, 'sop.trailer.ETX', 'ETX', '\x03','End of Message')
}
```

Then define the Header and Trailer objects. Note that these objects are actually composite fields.
```lua
local header = wsdh.Field.COMPOSITE{
	title = 'Header',
	SopFields.SOH,
	SopFields.LEN	
}

local trailer = wsdh.Field.COMPOSITE{
	title = 'Trailer',	
	SopFields.ETX
}
```

Now let's load the specs using the `loadSpecs` function of the `protoHelper` object. The parameters of this function are:

1. msgTypes		this is a table of message types. Each type has two properties: name and file.
1. dir			the directory were the CSV files are located
1. columns is a table with the mapping of columns:
	1. name is the name of the field name column. 
	1. length is the name of the field legth column. 
	1. type is the name of the field type column. Optional. Defaults to STRING.
	1. desc is the name of the field description column. Optional.
1. offset		the starting value for the offset column. Optional. Defaults to 0.
1. sep			the separator used in the csv file. Optional. Defaults to ','.
1. header		a composite or fixed length field to be added before the fields found in spec.
1. trailer		a composite or fixed length field to be added after the fields found in spec.

The function returns two tables. One containing the message specs and another containing parsers for the message specs. Each message spec has an id, a description and all the fields created from the CSV in a similar fashion to the one we used previously to create `SopFields`. Each message parser is specialized for a specific message type and they include the boilerplate code needed to handle the parsing of a message.

```lua

-- Column mapping. As described above.
local columns = { name = 'Field', 
				  length = 'Length', 
				  type = 'Type',
				  desc = 'Description' }

local msg_specs, msg_parsers = protoHelper:loadSpecs(msg_types,
													 SOP_SPECS_PATH,
													 columns,
													 header:len(),
													 ',',
													 header,
													 trailer)
```

Now let's create a few helper functions that will simplify the main parse function.

```lua
-- Returns the length of whole the message. Includes header and trailer.
local function getMsgLen(msgBuffer)
	return SopFields.SOH:len() + SopFields.LEN:len() + 
		   tonumber(protoHelper:getHeaderValue(msgBuffer, SopFields.LEN)) + 
		   trailer:len()
end

-- Returns the length of the message from the end of header up to the start of trailer.
local function getMsgDataLen(msgBuffer)
	return getMsgLen(msgBuffer) - header:len() - trailer:len()
end
```

One of the last steps and definatelly the most complicated is to create the function that validates a message, parses the message using one of the automatically generated message parsers and finally populates the tree in the *Packet Details* pane.
```lua
local function parseMessage(buffer, pinfo, tree)
	-- The minimum buffer length in that can be used to identify a message
	-- must include the header and the MessageType.
	local msgTypeLen = 2
	local minBufferLen = header:len() + msgTypeLen
	
	-- Messages start with SOH.
	if SopFields.SOH:value(buffer) ~= SopFields.SOH.fixedValue then
		protoHelper:trace('Frame: ' .. pinfo.number .. ' No SOH.')
		return 0
	end	

	-- Return missing message length in the case when the header is split between packets.	
	if buffer:len() <= minBufferLen then
		return -DESEGMENT_ONE_MORE_SEGMENT
	end

	-- Look for valid message types.
	local msgType = buffer(header:len(), msgTypeLen):string()
	local msgSpec = msg_specs[msgType]
	if not msgSpec then
		protoHelper:trace('Frame: ' .. pinfo.number .. ' Unknown message type: ' .. msgType)
		return 0
	end

	-- Return missing message length in the case when the data is split between packets.
	local msgLen = getMsgLen(buffer)
	local msgDataLen = getMsgDataLen(buffer)
	if buffer:len() < msgLen then
		protoHelper:trace('Frame: ' .. pinfo.number .. ' buffer:len < msgLen')
		return -DESEGMENT_ONE_MORE_SEGMENT
	end

	-- Select the parser that corresponds to this type of message.
	local msgParse = msg_parsers[msgType]
	-- If no parser is found for this type of message, reject the whole packet.
	if not msgParse then
		protoHelper:trace('Frame: ' .. pinfo.number .. ' Not supported message type: ' .. msgType)
		return 0
	end
	
	-- Parse the message and populate the tree.
	local bytesConsumed, subtree = msgParse(buffer, pinfo, tree, 0)
	
	-- Finally add some useful info to the protocol node of the tree. For this example we simply add the message type and length.
	subtree:append_text(', Type: ' .. msgType)	
	subtree:append_text(', Len: ' .. msgLen)

	pinfo.cols.protocol = sop.name	
	return bytesConsumed
end
```

Now that the parse function for the SOP protocol is ready, we need to create the dissector function using the `getDissector` helper function which returns a dissector function containing the basic while loop that pretty much all dissectors need to have. 
```lua
sop.dissector = protoHelper:getDissector(parseMessage)
```

Finally enable the dissector. `enableDissector` registers the ports to the TCP dissector table. 
```lua
protoHelper:enableDissector()
```

An example
----------

A detailed example can be found [here](examples/README.md).

Installation
------------

Add the following lines at the end of Wireshark's `init.lua` script:

``` lua
WSDH_SCRIPT_PATH="Replace this with the path to the directory src of the repo."
SOP_SPECS_PATH="Replace this with the path to the directory of the CSV specs."
dofile("Replace with full path to your dissector file.")
```

Testing
-------

At this point testing is manual. For an example have a look [here](examples/README.md#testing).

Acknowledgments
-------

Special thanks to the following people:

- FlavioJS and the Athena Dev Teams, for the [Athena dissector](http://paperlined.org/apps/wireshark/ArchivedLuaExamples/athena.lua) which was the starting point of this project.
- Geoff Leyland, for his [lua-csv](https://github.com/geoffleyland/lua-csv).
