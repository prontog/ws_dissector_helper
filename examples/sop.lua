-- Wireshard Dissector for the Simple Order Protocol (sop). An imaginary
-- protocol.
--
-- IMPORTANT: Add the following lines at the end of Wireshark's init.lua:
--
-- WSDH_SCRIPT_PATH='path to the directory 'src' of the repo'
-- SOP_SPECS_PATH='path to the directory of the CSV specs'
-- dofile('path to this file')
--
local wsdh = dofile(WSDH_SCRIPT_PATH .. '/ws_dissector_helper.lua')

local sop = Proto('SOP', 'Simple Order Protocol')
-- a table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line.
local defaultSettings = {
	ports = '9001-9010'
}
local SOP_VERSION = 2.0
local helper = wsdh.createProtoHelper(sop, SOP_VERSION)
helper:setDefaultPreference(defaultSettings)

local msg_types = { { name = 'NO', file = 'NO.csv' },
				    { name = 'OC', file = 'OC.csv' },
					{ name = 'TR', file = 'TR.csv' },
					{ name = 'RJ', file = 'RJ.csv' },
					{ name = 'EN', file = 'EN.csv' },
					{ name = 'BO', file = 'BO.csv' } }

-- Define fields
local SopFields = {
	SOH = wsdh.Field.FIXED(1,'sop.header.SOH', 'SOH', '\x01','Start of Header'),
	LEN = wsdh.Field.NUMERIC(3,'sop.header.LEN', 'LEN','Length of the payload (i.e. no header/trailer)'),
	ETX = wsdh.Field.FIXED(1, 'sop.trailer.ETX', 'ETX', '\x03','End of Message')
}
--Define Header
local header = wsdh.Field.COMPOSITE{
	title = 'Header',
	SopFields.SOH,
	SopFields.LEN
}
--Define Trailer
local trailer = wsdh.Field.COMPOSITE{
	title = 'Trailer',
	SopFields.ETX
}

-- Column mapping.
local columns = { name = 'Field',
				  length = 'Length',
				  type = 'Type',
				  desc = 'Description' }

local msg_specs, msg_parsers = helper:loadSpecs(msg_types,
												SOP_SPECS_PATH,
												columns,
												header:len(),
												',',
												header,
												trailer)

-- Returns the length of the message from the end of header up to the start
-- of trailer.
local function getMsgDataLen(msgBuffer)
	return tonumber(helper:getHeaderValue(msgBuffer, SopFields.LEN))
end

-- Returns the length of whole the message. Includes header and trailer.
local function getMsgLen(msgBuffer)
	local msgdataLen = getMsgDataLen(msgBuffer)
	if msgdataLen == nil then
		return nil
	end

	return header:len() + msgdataLen + trailer:len()
end

-- Parse a specific type of message from a buffer and add it to the tree.
local function parseMessage(buffer, pinfo, tree)
	-- The minimum buffer length in that can be used to identify a message
	-- must include the header and the MessageType.
	local msgTypeLen = 2
	local minBufferLen = header:len() + msgTypeLen
	-- Messages start with SOH.

	if SopFields.SOH:value(buffer) ~= SopFields.SOH.fixedValue then
		helper:warn('No SOH.')
		return 0
	end

	-- Return missing message length in the case when the header is split
	-- between packets.
	if buffer:len() <= minBufferLen then
		return -DESEGMENT_ONE_MORE_SEGMENT
	end

	-- Look for valid message types.
	local msgType = buffer(header:len(), msgTypeLen):string()
	local msgSpec = msg_specs[msgType]
	if not msgSpec then
		helper:warn('Unknown message type: ' .. msgType)
		return 0
	end

	-- Return missing message length in the case when the data is split
	-- between packets.
	local msgLen = getMsgLen(buffer)
	local msgDataLen = getMsgDataLen(buffer)
	if buffer:len() < msgLen then
		helper:info('buffer:len < msgLen [' .. buffer:len() .. ' < ' .. msgLen .. ']')
		return -DESEGMENT_ONE_MORE_SEGMENT
	end

	local msgParse = msg_parsers[msgType]
	-- If no parser is found for this type of message, reject the whole
	-- packet.
	if not msgParse then
		helper:warn('Not supported message type: ' .. msgType)
		return 0
	end

	local bytesConsumed, subtree = msgParse(buffer, pinfo, tree, 0)
    if bytesConsumed > 0 then
    	subtree:append_text(', Type: ' .. msgType)
    	subtree:append_text(', Len: ' .. msgLen)

    	pinfo.cols.protocol = sop.name
    end

	return bytesConsumed
end

sop.dissector = helper:getDissector(parseMessage)
helper:enableDissector()
