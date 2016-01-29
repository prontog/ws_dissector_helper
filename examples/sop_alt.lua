-- Wireshard Dissector for the Simple Order Protocol (sop). An imaginary
-- protocol. It uses the CSV specs that contain the header, payload and 
-- trailer fields.
--
-- IMPORTANT: Add the following lines at the end of Wireshark's init.lua:
--
-- WSDH_SCRIPT_PATH='path to the directory 'src' of the repo'
-- SOP_SPECS_PATH='path to the directory of the CSV specs'
-- dofile('path to this file')
--
local wsdh = dofile(WSDH_SCRIPT_PATH .. 'ws_dissector_helper.lua')

local sop = Proto('SOP_ALT', 'Simple Order Protocol - alt')
-- a table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line.
local defaultSettings = {
	ports = '9011-9020',
	trace = true
}
local helper = wsdh.createProtoHelper(sop)
helper:setDefaultPreference(defaultSettings)

local msg_types = { { name = 'NO', file = 'NO_full.csv' }, 
				    { name = 'OC', file = 'OC_full.csv' },
					{ name = 'TR', file = 'TR_full.csv' },
					{ name = 'RJ', file = 'RJ_full.csv' },
					{ name = 'EN', file = 'EN_full.csv' },
					{ name = 'BO', file = 'BO_full.csv' } }

-- Define fields
local SopFields = {
	SOH = wsdh.Field.FIXED(1,'sop_alt.SOH', 'SOH', '\x01','Start of Header'),
	LEN = wsdh.Field.NUMERIC(3,'sop_alt.LEN', 'LEN','Length of the payload (i.e. no header/trailer)'),	
	ETX = wsdh.Field.FIXED(1, 'sop_alt.ETX', 'ETX', '\x03','End of Message')
}
					
-- Column mapping.
local columns = { name = 'Field', 
				  length = 'Length', 
				  type = 'Type',
				  desc = 'Description' }

local msg_specs, msg_parsers = helper:loadSpecs(msg_types,
												SOP_SPECS_PATH,
												columns,
												0,
												',')

local header_len = 4
local trailer_len = 1
-- Returns the length of the message from the end of header up to the start
-- of trailer.
local function getMsgDataLen(msgBuffer)
	return SopFields.LEN:value(msgBuffer, SopFields.SOH:len())
end

-- Returns the length of whole the message. Includes header and trailer.
local function getMsgLen(msgBuffer)
	return header_len +
		   getMsgDataLen(msgBuffer) +
		   trailer_len
end

-- Parse a specific type of message from a buffer and add it to the tree.
local function parseMessage(buffer, pinfo, tree)
	-- The minimum buffer length in that can be used to identify a message
	-- must include the header and the MessageType.
	local msgTypeLen = 2
	local minBufferLen = header_len + msgTypeLen
	-- Messages start with SOH.

	if SopFields.SOH:value(buffer) ~= SopFields.SOH.fixedValue then
		helper:trace('Frame: ' .. pinfo.number .. ' No SOH.')
		return 0
	end	

	-- Return missing message length in the case when the header is split
	-- between packets.	
	if buffer:len() <= minBufferLen then
		return -DESEGMENT_ONE_MORE_SEGMENT
	end

	-- Look for valid message types.
	local msgType = buffer(header_len, msgTypeLen):string()
	local msgSpec = msg_specs[msgType]
	if not msgSpec then
		helper:trace('Frame: ' .. pinfo.number .. 
					 ' Unknown message type: ' .. msgType)
		return 0
	end

	-- Return missing message length in the case when the data is split
	-- between packets.
	local msgLen = getMsgLen(buffer)
	local msgDataLen = getMsgDataLen(buffer)
	if buffer:len() < msgLen then
		helper:trace('Frame: ' .. pinfo.number .. 
					 ' buffer:len < msgLen')
		return -DESEGMENT_ONE_MORE_SEGMENT
	end

	local msgParse = msg_parsers[msgType]
	-- If no parser is found for this type of message, reject the whole
	-- packet.
	if not msgParse then
		helper:trace('Frame: ' .. pinfo.number .. 
					 ' Not supported message type: ' .. msgType)
		return 0
	end
	
	local bytesConsumed, subtree = msgParse(buffer, pinfo, tree, 0)
	subtree:append_text(', Type: ' .. msgType)	
	subtree:append_text(', Len: ' .. msgLen)

	pinfo.cols.protocol = sop.name	
	return bytesConsumed
end

sop.dissector = helper:getDissector(parseMessage)
helper:enableDissector()
