local csv = dofile(WSDH_SCRIPT_PATH .. "csv.lua")

-------------------------------------------------
-- Inspired by the Athena dissector by FlavioJS.
-------------------------------------------------

local WSDH_VERSION = "0.3.1"
-- This object will be updated by the createProtoHelper function.
local wsdh = {
	createAbbr = function(self, name)
		return createAbbr(name)
	end,
	critical = function(self, ...)
		critical('wsdh Error:', ...)
	end,
	warn = function(self, ...)
		warn('wsdh Warn:', ...)
	end,
	message = function(self, ...)
		message('wsdh Message:', ...)
	end,
	info = function(self, ...)
		info('wsdh Info:', ...)
	end,
	debug = function(self, ...)
		debug('wsdh Debug:', ...)
	end,
	trace = function(self, ...)
		debug('wsdh Debug:', ...)
	end
}

-- Field table will contain
local Field = {}

local fieldRepo = {}

local function createAbbr(name)
	return string.lower(string.gsub(name, '[^%a%d%._]', ''))
end

-- Returns a ProtoField from the fieldRepo. If it does not exist,
-- it is first created and added to the repo.
local function createProtoField(abbr, name, desc, len, type)
	assert(abbr, 'columns cannot be nil')
	assert(name, 'columns cannot be nil')
	local len = len or ''
	local type = type or 'STRING'

	local ftype = nil
	if type == 'NUMERIC' then
		ftype = ftypes.FLOAT
	else
		ftype = ftypes.STRING
	end

	local repoFieldName = abbr
	local f = fieldRepo[repoFieldName]

	-- If a field with the same abbr exists in the repo we need to check
	-- the type and length as well. All three should much. Otherwise we
	-- need to create a new ProtoField.
	if f and f.len ~= len then
		wsdh:info('A field with name "' .. f.name .. '" and different length (' .. f.len .. ') already exists.')
		repoFieldName = repoFieldName .. len
		f = fieldRepo[repoFieldName]
	end

	local protoField = nil

	if f then
		protoField = f.protoField
	else
		protoField = ProtoField.new(name, repoFieldName, ftype, nil, nil, nil, desc)
		fieldRepo[repoFieldName] = { name = name,
									  abbr = abbr,
									  len = len,
									  ftype = ftype,
									  desc = desc,
									  protoField = protoField }
	end

	return protoField
end

function Field.FIXED(len, abbr, name, fixedValue, desc, offset)
	assert(fixedValue, 'fixedValue cannot be nil')
	return {
		proto = createProtoField(abbr, name, desc, len),
		type = 'FIXED',
		len = function()
			return len
		end,
		offset = offset,
		abbr = abbr,
		name = name,
		value = function(self, tvb, off)
			wsdh:debug(self.type .. '.value of field ' .. self.name)
			local buf = tvb(off, self:len())
			return buf:string(), buf
		end,
		valueSingle = function(self, tvb, off)
			local value, buf = self:value(tvb, off)
			return value
		end,
		fixedValue = fixedValue,
		add_to = function(self, tree, tvb, off)
			wsdh:debug(self.type .. '.add_to of field ' .. self.name)
			local value, buf = self:value(tvb, off)
			if value ~= self.fixedValue then
				wsdh:warn('field ' .. self.name ..
						   ' has invalid fixed value [expected: ' ..
						   self.fixedValue .. ', got: ' .. value .. ']')
				return 0
			end

			local subTree = nil
			if tree then
				subTree = tree:add(self.proto, buf, value)
			end
			return self:len(), subTree
		end
	}
end

function Field.STRING(len, abbr, name, desc, offset, optional)
	return {
		proto = createProtoField(abbr, name, desc, len),
		type = 'STRING',
		len = function()
			return len
		end,
		offset = offset,
		abbr = abbr,
		name = name,
		optional = optional or false,
		value = function(self, tvb, off)
			wsdh:debug(self.type .. '.value of field ' .. self.name)
			off = off or self.offset
			if off + self:len() > tvb:len() then
				return nil, nil
			end

			if self.optional and wsdh.getMsgLen then
				if off + self:len() > wsdh:getMsgLen(tvb) then
					wsdh:debug(self.type .. ' length missmatch. off + self:len() > wsdh:getMsgLen(tvb) [' .. off + self:len() .. ' > ' .. wsdh:getMsgLen(tvb) .. ']')
					return nil, nil
				end
			end

			local buf = tvb(off, self:len())
			return buf:string(), buf
		end,
		valueSingle = function(self, tvb, off)
			local value, buf = self:value(tvb, off)
			return value
		end,
		add_to = function(self, tree, tvb, off)
			wsdh:debug(self.type .. '.add_to of field ' .. self.name)
			local value, buf = self:value(tvb, off)
			local valueLen = self:len()
			local subTree = nil

			if value == nil then
				value = 0
				valueLen = 0

				if self.optional then
					return valueLen, subTree
				end
			end

			if tree then
				subTree = tree:add(self.proto, buf, value)
			end

			return valueLen, subTree
		end
	}
end

function Field.OPTIONAL(len, abbr, name, desc, offset)
	f = Field.STRING(len, abbr, name, desc, offset, true)
	f.type = 'OPTIONAL'
	return f
end

function Field.NUMERIC(len, abbr, name, desc, offset)
	return {
		proto = createProtoField(abbr, name, desc, len, 'NUMERIC'),
		type = 'NUMERIC',
		len = function()
			return len
		end,
		offset = offset,
		abbr = abbr,
		name = name,
		value = function(self, tvb, off)
			wsdh:debug(self.type .. '.value of field ' .. self.name)
			off = off or self.offset
			local buf = tvb(off, self:len())
			return tonumber(buf:string()), buf
		end,
		valueSingle = function(self, tvb, off)
			local value, buf = self:value(tvb, off)
			return value
		end,
		add_to = function(self, tree, tvb, off)
			wsdh:debug(self.type .. '.add_to of field ' .. self.name)
			local value, buf = self:value(tvb, off)
			local valueLen = self:len()

			if value == nil then
				wsdh:warn('NUMERIC field ' .. self.name ..  ' with invalid value [' .. tvb(off, valueLen):string() .. ']. Could be a locale issue (floating point).')
				value = 0
				valueLen = 0
			end

			local subTree = nil
			if tree then
				subTree = tree:add(self.proto, buf, value)
			end
			return valueLen, subTree
		end
	}
end

function Field.VARLEN(lenField, abbr, name, desc, offset)
	return {
		proto = createProtoField(abbr, name, desc, lenField.abbr),
		type = 'STRING',
		lenField = lenField,
		len = function(self, tvb)
			assert(tvb, 'tvb cannot be nil')
			return self.lenField:valueSingle(tvb)
		end,
		offset = offset,
		abbr = abbr,
		name = name,
		value = function(self, tvb, off)
			wsdh:debug(self.type .. '.value of field ' .. self.name)
			off = off or self.offset
			local buf = tvb(off, self:len(tvb))
			return buf:string(), buf
		end,
		valueSingle = function(self, tvb, off)
			local value, buf = self:value(tvb, off)
			return value
		end,
		add_to = function(self, tree, tvb, off)
			wsdh:debug(self.type .. '.add_to of field ' .. self.name)
			local value, buf = self:value(tvb, off)

			local subTree = nil
			if tree then
				subTree = tree:add(self.proto, buf, value)
			end
			return string.len(value), subTree
		end
	}
end

function Field.COMPOSITE(fields)
	return {
		proto = createProtoField(wsdh:createAbbr(fields.title), fields.title, "", 0, 'COMPOSITE'),
		type = 'COMPOSITE',
		fields = fields,
		title = fields.title,
		name = fields.title,
		len = function(self)
			-- Because of OPTIONAL fields, there is no way to know the length of
			-- a COMPOSITE before parsing. So if a field is OPTIONAL, return two
			-- two lengths, the required and the optional (includes the
			-- required).
			local requiredLen = 0
			local optionalLen = 0
			for _, field in ipairs(self.fields) do
				if field.optional then
					optionalLen = field:len()
				else
					requiredLen = requiredLen + field:len()
				end
			end
			return requiredLen, requiredLen + optionalLen
		end,
		value = function(self, tvb, off)
			wsdh:debug(self.type .. '.value of field ' .. self.name)
			-- Note that field_len is only the required fields. If there is an
			-- OPTIONAL field at the end of the COMPOSITE, it cannot be handled
			-- and the returned value will not include it.
			local fieldLen, optionalLen = self:len()
			if off + optionalLen <= tvb:len() then
				if fieldLen ~= optionalLen and wsdh.getMsgLen then
					if off + optionalLen > wsdh:getMsgLen(tvb) then
						wsdh:debug(self.type .. ' length missmatch. off + optionalLen > wsdh:getMsgLen(tvb) [' .. off + optionalLen .. ' > ' .. wsdh:getMsgLen(tvb) .. ']. Discarding optionalLen.')
					else
						fieldLen = optionalLen
					end
				else
					fieldLen = optionalLen
				end
			end

			if off + fieldLen > tvb:len() then
				wsdh:warn(self.type .. ' length missmatch. off + fieldLen > tvb:len() [' .. off + fieldLen .. ' ~= ' .. tvb:len() .. ']')
				fieldLen = tvb:len() - off
			end
			return tvb(off, fieldLen):string(), tvb(off, fieldLen)
		end,
		getOffset = function(self, abbr1)
			local offset = 0;
			for _, field in ipairs(self.fields) do
				if field.abbr == abbr1 then
					return offset
				else
					offset = offset + field:len()
				end
			end
			return -1
		end,
		add_to = function(self, tree, tvb, off)
			wsdh:debug(self.type .. '.add_to of field ' .. self.name)
			local value, buf = self:value(tvb, off)

			local subTree = nil
			if tree then
				subTree = tree:add(self.proto, buf)
			end

			local addedBytes = 0
			for _, field in ipairs(self.fields) do
				local fieldLen = field:add_to(subTree, tvb, off + addedBytes)
				if fieldLen == 0 and not field.optional then
					return 0
				end
				addedBytes = addedBytes + fieldLen
			end

			if subTree then
				subTree:set_len(addedBytes)
			end
			return addedBytes, subTree
		end
	}
end

function Field.REPEATING(repeatsField, compositeField)
	assert(repeatsField, 'repeatsField cannot be nil')
	assert(compositeField, 'compositeField cannot be nil')
	-- Make sure no OPTIONAL field is in the REPEATING group.
	for _, field in ipairs(repeatsField) do
		assert(not field.optional, 'Invalid optional field ' .. field.name ..
		       ' in REPEATING field ' .. compositeField.title ..
			   '. Optional fields are only allowed at the end of a message.')
	end
	return {
		type = 'REPEATING',
		repeatsField = repeatsField,
		composite = compositeField,
		title = compositeField.title,
		name = compositeField.title,
		len = function(self)
			return self.composite:len()
		end,
		add_to = function(self, tree, tvb, off)
			wsdh:debug(self.type .. '.add_to of field ' .. self.name)
			local repeats = tonumber(self.repeatsField:valueSingle(tvb))
			if repeats == nil then
				wsdh:debug('repeatsField is not a number [' .. tostring(repeats) .. ']')
				return 0
			end
			local addedBytes = 0
			for i = 1, repeats do
				local fieldLen, subTree = self.composite:add_to(tree, tvb, off + addedBytes)
				if fieldLen == 0 then
					return 0
				end

				if subTree then
					subTree:append_text(' ' .. i)
				end

				addedBytes = addedBytes + fieldLen
			end
			return addedBytes, tree
		end
	}
end

Field['REPEATING-END'] = 'dummy'

--[[
	Read a message spec from a CSV file.

	filename is the name of the CSV file.
	columns is a table with the following keys:
		name    the column containng the field name.
		length  the column containng the field length.
		type    the column containng the field type. Optional. Defaults to STRING.
		desc    the column containng the field description. Optional.
		other   the column containng the othe field information. Optional. Can
		        be used with Field.FIXED to pass the FIXED value.
	abbrPrefix is the prefix for the abbr column, which is simply the name with
		any	spaces and non-printable characters removed. Optional. Defaults to ''.
	offset is the starting value for the offset column. Optional. Defaults to 0.
	sep is the separator used in the csv file. Optional. Defaults to ','.

	Returns a table with the following columns: { name, abbr, len, offset, type, desc }
--]]
local function readMsgSpec(fileName, columns, abbrPrefix, offset, sep)
	local f = csv.open(fileName, { separator = sep or ',', header = true })
	assert(f, 'fileName ' .. fileName .. ' does not exist')
	assert(columns, 'columns cannot be nil')
	assert(columns.name, 'columns.name cannot be nil')
	assert(columns.length,'columns.length cannot be nil')
	abbrPrefix = abbrPrefix or ''
	offset = offset or 0

	local spec = {}

	local i = 1
	for ln in f:lines() do
		local length = ln[columns.length]
		local name = ln[columns.name]
		local type = ln[columns.type] or ""

		assert(name, 'name ' .. columns.name .. ' from file ' .. fileName .. ' does not exist' )
		assert(length, 'length ' .. columns.length .. ' from file ' .. fileName .. ' does not exist' )
		-- Rows with non-numeric values in the 'len' column are skipped in the offset
		-- calculation. These fields can signify a repeating field with the len equal
		-- to the abbr of an already existing field signifying the number of repeats.
		if not tonumber(length) then
			length = createAbbr(abbrPrefix .. length)
		end

		local fieldType = string.upper(type)
		if not Field[fieldType] then
			fieldType = 'STRING'
		end

		local desc = ln[columns.desc]
		local other = ln[columns.other]

		spec[i] = { name = name,
					abbr = createAbbr(abbrPrefix .. name),
					len = length,
					offset = offset,
					type = fieldType,
					desc = desc,
					other =  other}

		-- Again length can be string. See previous comment.
		if tonumber(length) then
			offset = offset + length
		end
		i = i + 1
	end

	return spec
end

local function fieldByAbbr(abbr, fields)
	for i, f in ipairs(fields) do
		if f.abbr == abbr then
			return f
		end
	end

	return nil
end

local function createSimpleField(spec)
	local newField = nil

	if spec.type == 'NUMERIC' then
		newField = Field.NUMERIC(spec.len, spec.abbr, spec.name, spec.desc, spec.offset)
	elseif spec.type == 'FIXED' then
		newField = Field.FIXED(spec.len, spec.abbr, spec.name, spec.other, spec.desc, spec.offset)
	else
		newField = Field.STRING(spec.len, spec.abbr, spec.name, spec.desc, spec.offset)
	end

	return newField
end

-- Converts a spec to Field.XXXX.
--
-- id is the message type/id. description is a text field
-- describing the message type. msgSpec must be of the same format as the output
-- of readMsgSpec. header is a Field to be added before the fields found in spec.
-- trailer is a Field to be added after the fields found in spec.
local function msgSpecToFieldSpec(id, description, msgSpec, header, trailer)
	assert(id, 'id cannot be nil')
	description = description or ''
	assert(msgSpec, 'msgSpec cannot be nil')

	-- Create Field.X object for each field in the spec
	local bodyFields = {}
	local i = 1
	while i <= #msgSpec do
		local f = msgSpec[i]

		if f.type == 'REPEATING' then
			local lenField = fieldByAbbr(f.len, bodyFields)
			assert(lenField, f.len .. ' does not match an existing abbr in message ' .. id)

			local repeatingFields = {}
			local ii = i + 1
			while ii <= #msgSpec do
				local ff = msgSpec[ii]

				if ff.type == 'REPEATING-END' then
					break
				end

				repeatingFields[#repeatingFields + 1] = createSimpleField(ff)
				ii = ii + 1
			end
			i = ii
			repeatingFields['title'] = f.name

			local repeatingComposite = Field.COMPOSITE(repeatingFields)
			bodyFields[#bodyFields + 1] = Field.REPEATING(lenField, repeatingComposite)
		elseif f.type == 'VARLEN' then
			local lenField = fieldByAbbr(f.len, bodyFields)
			assert(lenField, f.len .. ' does not match an existing abbr in message ' .. id)

			bodyFields[#bodyFields + 1] = Field.VARLEN(lenField,
													   f.abbr,
													   f.name,
													   f.desc,
													   f.offset)
	    elseif f.type == 'OPTIONAL' then
		   assert(i == #msgSpec, 'Invalid optional field ' .. f.name .. ' in message ' .. id .. '. Optional fields are only allowed at the end of a message.')

		   bodyFields[#bodyFields + 1] = Field.OPTIONAL(f.len,
													    f.abbr,
													    f.name,
													    f.desc,
													    f.offset)
		else -- Everything else is a simple type
			bodyFields[#bodyFields + 1] = createSimpleField(f)
		end

		i = i + 1
	end
	bodyFields['title'] = 'Body'

	local msgFields = {}
	-- First add all elements with indices
	if header then
		msgFields[1] = header
		msgFields[#msgFields + 1] = Field.COMPOSITE(bodyFields)
	else
		for i, f in ipairs(bodyFields) do
			msgFields[#msgFields + 1] = f
		end
	end

	if trailer then
		msgFields[#msgFields + 1] = trailer
	end

	-- Then add all named elements
	msgFields['id'] = id
	msgFields['description'] = description

	return msgFields
end


local TRACE_LEVEL_OFF = 0
local TRACE_LEVEL_CRTITICAL = 1
local TRACE_LEVEL_WARN = 2
local TRACE_LEVEL_MESSAGE = 3
local TRACE_LEVEL_INFO = 4
local TRACE_LEVEL_DEBUG = 5

local trace_levels = {
	{ 0, "Off", TRACE_LEVEL_OFF },
	{ 1, "Critical", TRACE_LEVEL_CRTITICAL },
	{ 2, "Warning", TRACE_LEVEL_WARN },
	{ 3, "Information", TRACE_LEVEL_MESSAGE },
	{ 4, "Info", TRACE_LEVEL_INFO },
	{ 5, "Debug", TRACE_LEVEL_DEBUG }
}

--[[
	Creates ws_dissector_helper for a protocol.
		proto is the Wireshark Proto
		version is the version of the protocol version (optional)
--]]
local function createProtoHelper(proto, version)
	assert(proto, 'proto cannot be nil')

	wsdh = {
		version = version,
		protocol = proto,
		critical = function(self, ...)
			if self.protocol.prefs.trace_level >= TRACE_LEVEL_CRTITICAL then
				critical(os.date('%H:%M:%S ',os.time()) .. self.protocol.name .. ' #' .. tostring(self.frame) .. ' [critical]: ', ...)
			end
		end,
		warn = function(self, ...)
			if self.protocol.prefs.trace_level >= TRACE_LEVEL_WARN then
				warn(os.date('%H:%M:%S ',os.time()) .. self.protocol.name .. '#' .. tostring(self.frame) .. ' [warn]:', ...)
			end
		end,
		message = function(self, ...)
			if self.protocol.prefs.trace_level >= TRACE_LEVEL_MESSAGE then
				message(os.date('%H:%M:%S ',os.time()) .. self.protocol.name .. '#' .. tostring(self.frame) .. ' [message]:', ...)
			end
		end,
		info = function(self, ...)
			if self.protocol.prefs.trace_level >= TRACE_LEVEL_INFO then
				info(os.date('%H:%M:%S ',os.time()) .. self.protocol.name .. '#' .. tostring(self.frame) .. ' [info]:', ...)
			end
		end,
		debug = function(self, ...)
			if self.protocol.prefs.trace_level >= TRACE_LEVEL_DEBUG then
				debug(os.date('%H:%M:%S ',os.time()) .. self.protocol.name .. '#' .. tostring(self.frame) .. ' [debug]:', ...)
			end
		end,
		-- Exactly the same with debug. Kept for backwards copatibility.
		trace = function(self, ...)
			self:debug(...)
		end,
		printMsgSpec = function(self, spec)
			self:debug('index', 'name', 'abbr', 'len', 'offset', 'type', 'desc')
			for i, field in ipairs(spec) do
				self:debug(i, field.name, field.abbr, field.len,
						   field.offset, field.type, field.desc)
			end
		end,
		printField = function(self, field)
			if field.type == 'COMPOSITE' then
				for i, f in ipairs(field.fields) do
					self:printField(f)
				end
			elseif field.type == 'REPEATING' then
				self:printField(field.composite)
			elseif field.type then
				self:debug(field.proto)
			end
		end,
		printFieldSpec = function(self, spec)
			self:debug('field spec: ' .. spec.id)
			for i, field in ipairs(spec) do
				self:printField(field)
			end
		end,
		-- Returns a dissector function containing the basic while loop that callback
		-- the parseFunction. Can handle TCP reassembly.
		getDissector = function(self, parseFunction)
			local dissector = function(buffer, pinfo, tree)
				wsdh.frame = pinfo.number

				-- Ignore cut off packets
				if buffer:len() ~= buffer:reported_len() then
					self:warn('Frame length missmatch. buffer:len ~= buffer:reported_len [' .. buffer:len() .. ' ~= ' .. buffer:reported_len() .. ']')
					return 0
				end

				local bytesConsumed = 0
				while (bytesConsumed < buffer:len()) do
					self:info(buffer(bytesConsumed):string())
					local msgLength = parseFunction(buffer(bytesConsumed), pinfo, tree)
					if msgLength > 0 then
						self:info('Parsed message of size ' .. msgLength .. '.')
						bytesConsumed = bytesConsumed + msgLength
					elseif msgLength == 0 then
						if bytesConsumed > 0 then
							self:warn('Parsing the message did not complete. Skipping the rest of the packet.')
							return
						else
							self:warn('Parsing failed. Skipping packet.')
							return 0
						end
					else
						-- Negative length is for the mising bytes. Invert to a
						-- positive number and ask Wireshark for TCP reassembly.
						msgLength = - msgLength
						self:info('Incomplete message.', 'bytesConsumed:' .. bytesConsumed, 'missing:' .. msgLength)
						-- we need more bytes, so set the desegment_offset to what we
						-- already consumed, and the desegment_len to how many more
						-- are needed
						pinfo.desegment_offset = bytesConsumed
						pinfo.desegment_len = msgLength
						return
					end
				end
			end
			return dissector
		end,
		-- Enables the protocol. Uses protocol preferences
		enableDissector = function(self, transportProtocol)
			self:debug('enabling dissector')
			local tcp_port = DissectorTable.get('tcp.port')
			tcp_port:add(self.protocol.prefs.ports, self.protocol)
		end,
		-- Disables the protocol.
		disableDissector = function(self)
			self:debug('disabling dissector')
			local tcp_port = DissectorTable.get('tcp.port')
			tcp_port:remove_all(self.protocol)
		end,
		-- Set the default preferences for the protocol.
		setDefaultPreference = function(self, defaultPrefs)
			assert(defaultPrefs, 'defaultPrefs cannot be nil')

			self.protocol.prefs.ports = Pref.range('Ports',
											  defaultPrefs.ports,
											  'Port range (i.e. 7001-7010,8005,8100)',
											  65535)
			self.protocol.prefs.trace_level = Pref.enum('Trace level',
											 defaultPrefs.trace_level or TRACE_LEVEL_WARN,
											 'Sets the level of tracing on stderr and Lua console. Note that Debug level is very verbose but can be very helpful for troubleshooting a dissector.',
										     trace_levels,
										     false)



	        if self.version then
				self.protocol.prefs.version = Pref.statictext('Protocol version: ' .. self.version)
			end

		    self.protocol.prefs.info = Pref.statictext('Powered by ws_dissector_helper v' .. WSDH_VERSION .. ' https://github.com/prontog/ws_dissector_helper')

			self.protocol.prefs_changed = function()
				self:disableDissector()
				self:enableDissector()
			end
		end,
		-- Create a parser function for specific message spec.
		createParser = function(self, fieldsSpec)
			assert(fieldsSpec, 'fieldsSpec cannot be nil')

			return function(buf, pkt, root)
				local bytesValidated = 0
				-- Validate first.
				for i, field in ipairs(fieldsSpec) do
					self:debug('Validating field ' .. field.name)
					local fieldLen = field:add_to(nil, buf, bytesValidated)
					if fieldLen == 0 and not field.optional then
						-- Return without adding anything to the tree.
						self:debug('field ' .. field.name .. ' is not valid.')
						return 0
					end
					bytesValidated = bytesValidated + fieldLen
				end

				if self.getMsgLen then
				 	if bytesValidated ~= self:getMsgLen(buf) then
						self:debug('length missmatch. bytesValidated ~= self:getMsgLen(buf) [' .. bytesValidated .. ' ~= ' .. self:getMsgLen(buf) .. ']')
						return 0
					end
				end

				-- Start adding to the tree.
				local bytesConsumed = 0
				local subtree = root:add(self.protocol,
										 buf(),
										 self.protocol.name .. ' Protocol')

				for i, field in ipairs(fieldsSpec) do
					if field.type then
						self:debug('Adding field ' .. field.name)
						local fieldLen = field:add_to(subtree, buf, bytesConsumed)
						if fieldLen == 0 and not field.optional then
							self:debug('field ' .. field.name .. ' is empty.')
							return 0
						end
						bytesConsumed = bytesConsumed + fieldLen
					end
				end

				subtree:set_len(bytesConsumed)

				return bytesConsumed, subtree
			end
		end,
		loadSpecs = function(self, msgTypes, dir, columns, offset, sep, header, trailer)
			local specs = {}
			local msgSpecs = {}
			local msgParsers = {}
			-- Read the CSV files into specs.
			for i, v in ipairs(msgTypes) do
				specs[v.name] = readMsgSpec(dir .. "/" .. v.file,
									   columns,
									   self.abbrPrefix,
									   offset,
									   sep)
				if self.protocol.prefs.trace_level >= TRACE_LEVEL_DEBUG then
					self:printMsgSpec(specs[v.name])
				end
				msgSpecs[v.name] = msgSpecToFieldSpec(v.name, v.name .. ' message', specs[v.name], header, trailer)
				if self.protocol.prefs.trace_level >= TRACE_LEVEL_DEBUG then
					self:printFieldSpec(msgSpecs[v.name])
				end
				msgParsers[v.name] = self:createParser(msgSpecs[v.name])
			end

			for i, f in pairs(fieldRepo) do
				self:debug('Adding ' .. i .. ' to proto.fields')
				table.insert(self.protocol.fields, f.protoField)
			end

			self.header = header
			self.trailer = trailer

			return msgSpecs, msgParsers
		end,
		-- Returns the value of specific field of the header.
		getHeaderValue = function (self, msgBuffer, headerField)
			assert(msgBuffer, 'msgBuffer cannot be nil')
			assert(headerField, 'headerField cannot be nil')
			assert(self.header, 'self.header is nil')

			return headerField:valueSingle(msgBuffer, self.header:getOffset(headerField.abbr))
		end,
		-- Returns the value of specific field of the trailer.
		getTrailerValue = function (self, msgBuffer, trailerField)
			assert(msgBuffer, 'msgBuffer cannot be nil')
			assert(trailerField, 'trailerField cannot be nil')
			assert(self.trailer, 'self.trailer is nil')

			return trailerField:valueSingle(msgBuffer, self.trailer:getOffset(trailerField.abbr))
		end,
		abbrPrefix = string.lower(proto.name) .. '.',
		createAbbr = function(self, name)
			return createAbbr(self.abbrPrefix .. name)
		end,
		Field = Field,
		readMsgSpec = readMsgSpec,
		msgSpecToFieldSpec = msgSpecToFieldSpec,
		createSimpleField = createSimpleField
	}

	return wsdh
end

return {
	Field = Field,
	readMsgSpec = readMsgSpec,
	msgSpecToFieldSpec = msgSpecToFieldSpec,
	createProtoHelper = createProtoHelper,
	createSimpleField = createSimpleField
}
