local csv = dofile(WSDH_SCRIPT_PATH .. "csv.lua")

----------------------------------------
-- Based on the version from http://paperlined.org/apps/wireshark/ArchivedLuaExamples/athena.lua
-- which was the starting point of this project.
----------------------------------------

local wsdh = {}

-- Field table will contain 
local Field = {}

Field.repo = {}

-- Returns a ProtoField from the Field.repo. If it does not exist,
-- it is first created and added to the repo. 
local function createProtoField(abbr, name, desc, len, type)
	local len = len or ''
	local len = len or ''
	local type = type or 'STRING'
	
	local ftype = nil
	if type == 'NUMERIC' then
		ftype = ftypes.FLOAT
	else
		ftype = ftypes.STRING
	end	
	
	local repoFieldName = abbr	
	local f = Field.repo[repoFieldName]
	
	-- If a field with the same abbr exists in the repo we need to check
	-- the type and length as well. All three should much. Otherwise we
	-- need to create a new ProtoField.
	if f and f.len ~= len then
		warn('A field with name ' .. f.name .. ' and different length already exists.')
		repoFieldName = repoFieldName .. len
		f = Field.repo[repoFieldName]
	end
	
	local protoField = nil
	
	if f then
		protoField = f.protoField
	else
		--print(repoFieldName)
		protoField = ProtoField.new(name, repoFieldName, ftype, nil, nil, nil, desc)
		--print('ok')
		Field.repo[repoFieldName] = { name = name,
									  abbr = abbr,
									  len = len,
									  ftype = ftype,
									  desc = desc,
									  protoField = protoField }
	end
	
	return protoField
end

function Field.FIXED(len, abbr, name, fixedValue, desc)
	return {
		proto = createProtoField(abbr, name, desc, len),
		type = 'FIXED',
		len = function() 
			return len
		end,
		abbr = abbr,
		name = name,
		value = function(self, tvb, off)
			local buf = tvb(off, self:len())
			return buf:string(), buf
		end,
		valueSingle = function(self, tvb, off)
			local value, buf = self:value(tvb, off)
			return value
		end,
		fixedValue = fixedValue,
		add_to = function(self, tree, tvb, off)
			local value, buf = self:value(tvb, off)
			local subTree = tree:add(self.proto, buf, value)
			return self:len(), subTree
		end
	}
end

function Field.STRING(len, abbr, name, desc, offset)	
	return {
		proto = createProtoField(abbr, name, desc, len),
		type = 'STRING',
		len = function() 
			return len
		end,
		offset = offset,
		abbr = abbr,
		name = name,
		value = function(self, tvb, off)			
			off = off or offset
			local buf = tvb(off, self:len())
			return buf:string(), buf
		end,
		valueSingle = function(self, tvb, off)
			local value, buf = self:value(tvb, off)
			return value
		end,
		add_to = function(self, tree, tvb, off)
			local value, buf = self:value(tvb, off)
			local subTree = tree:add(self.proto, buf, value)
			return self:len(), subTree
		end
	}
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
			off = off or offset
			local buf = tvb(off, self:len())
			return tonumber(buf:string()), buf
		end,
		valueSingle = function(self, tvb, off)
			local value, buf = self:value(tvb, off)
			return value
		end,
		add_to = function(self, tree, tvb, off)
			local value, buf = self:value(tvb, off)
			local subTree = tree:add(self.proto, buf, value)
			return self:len(), subTree
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
			off = off or offset
			local buf = tvb(off, self:len(tvb))
			return buf:string(), buf
		end,
		valueSingle = function(self, tvb, off)
			local value, buf = self:value(tvb, off)
			return value
		end,
		add_to = function(self, tree, tvb, off)			
			local value, buf = self:value(tvb, off)
			local subTree = tree:add(self.proto, buf, value)
			return string.len(value), subTree
		end
	}
end

function Field.COMPOSITE(fields)	
	return {
		type = 'COMPOSITE',
		fields = fields,
		title = fields.title,
		len = function(self)
			local length = 0
			for _, field in ipairs(fields) do			
				length = length + field:len()
			end
			return length
		end,
		value = function(self, tvb, off)
			return fields.title, tvb(off)
		end,
		getOffset = function(self, abbr1)			
			local offset = 0;
			for _, field in ipairs(fields) do
				if field.abbr == abbr1 then
					return offset
				else
					offset = offset + field:len()
				end
			end			
			return -1
		end,
		add_to = function(self, tree, tvb, off)
			local value, buf = self:value(tvb, off)
			local subTree = tree:add(buf, value)			
			
			local addedBytes = 0
			for _, field in ipairs(fields) do
				local fieldLen = field:add_to(subTree, tvb, off + addedBytes)				
				addedBytes = addedBytes + fieldLen
			end
			subTree:set_len(addedBytes)
			return addedBytes, subTree
		end
	}
end

function Field.REPEATING(repeatsField, compositeField)	
	return {
		type = 'REPEATING',
		repeatsField = repeatsField,		
		composite = compositeField,		
		title = compositeField.title,
		len = function(self)			
			return self.composite:len()
		end,
		add_to = function(self, tree, tvb, off)		
			local repeats = self.repeatsField:valueSingle(tvb)		
			local addedBytes = 0
			for i = 1, repeats do
				local fieldLen, subTree = self.composite:add_to(tree, tvb, off + addedBytes)
				subTree:append_text(' ' .. i)
				addedBytes = addedBytes + fieldLen
			end
			return addedBytes, tree
		end
	}
end

--[[ 
	Read a message spec from a CSV file. 

	filename is the name of the CSV file.
	columns is a table with the mapping of columns:
		name is the name of the field name column. 
		length is the name of the field length column. 
		type is the name of the field type column. Optional. Defaults to STRING.
		desc is the name of the field description column. Optional.
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

	local function createAbbr(name)
		return string.lower(abbrPrefix .. string.gsub(name, '[^%a%d]', ''))
	end
	
	local function validateType(fieldType)
		return Field[fieldType]
	end
	
	local spec = {}

	local i = 1
	for ln in f:lines() do
		local length = ln[columns.length]
		local name = ln[columns.name]
		
		assert(name, 'name ' .. columns.name .. ' does not exist' )
		assert(length, 'length ' .. columns.name .. ' does not exist' )		
		-- Rows with non-numeric values in the 'len' column are skipped in the offset
		-- calculation. These fields can signify a repeating field with the len equal
		-- to the abbr of an already existing field signifying the number of repeats.		
		if not tonumber(length) then
			length = createAbbr(length)
		end
		
		local fieldType = ln[columns.type]
		if not Field[fieldType] then
			fieldType = 'STRING'
		end
		
		local desc = ln[columns.desc]
		
		spec[i] = { name = name, 
					abbr = createAbbr(name), 
					len = length, 
					offset = offset,
					type = fieldType,
					desc = desc	}

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
	else
		newField = Field.STRING(spec.len, spec.abbr, spec.name, spec.desc, spec.offset)
	end
	
	return newField
end

-- Converts a spec to Field.XXXX. id is the message type/id. description is a text field 
-- describing the message type. spec must be of the same format as the output
-- of readSpec. header is a Field to be added before the fields found in spec. 
-- trailer is a Field to be added after the fields found in spec.
local function msgSpecToFieldSpec(id, description, msgSpec, header, trailer)	
	assert(id, 'id cannot be nil');
	description = description or ''
	assert(msgSpec, 'msgSpec cannot be nil');	

	-- Create Field.X object for each field in the spec
	local bodyFields = {}	
	for i, f in ipairs(msgSpec) do
		-- Handle complex types.
		if f.type == 'REPEATING' then
			local lenField = fieldByAbbr(f.len, bodyFields)
			assert(lenField, f.len .. ' does not match an existing abbr in message ' .. id)
			
			local repeatingFields = {}
			for ii = i + 1, #msgSpec do
				local ff = msgSpec[ii]
				repeatingFields[#repeatingFields + 1] = createSimpleField(ff)
			end
			repeatingFields['title'] = f.name
			
			local repeatingComposite = Field.COMPOSITE(repeatingFields)
			bodyFields[#bodyFields + 1] = Field.REPEATING(lenField, repeatingComposite)			
			break
		elseif f.type == 'VARLEN' then
			local lenField = fieldByAbbr(f.len, bodyFields)
			assert(lenField, f.len .. ' does not match an existing abbr in message ' .. id)
			
			bodyFields[#bodyFields + 1] = Field.VARLEN(lenField,
													   f.abbr,
													   f.name,
													   f.desc,
													   f.offset)
		else -- Everything else is a simple type
			bodyFields[#bodyFields + 1] = createSimpleField(f)
		end
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

local function createProtoHelper(proto)
	assert(proto, 'proto cannot be nil');
	return {
		protocol = proto,
		trace = function(self, ...)		
			if self.protocol.prefs.trace then
				debug(self.protocol.name .. ' Trace:', ...)
			end		
		end,
		printMsgSpec = function(self, spec)		
			self:trace('index', 'name', 'abbr', 'len', 'offset', 'type', 'desc')
			for i, field in ipairs(spec) do		
				self:trace(i, field.name, field.abbr, field.len,
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
				self:trace(field.proto)
			end
		end,
		printFieldSpec = function(self, spec)
			self:trace('field spec: ' .. spec.id)
			for i, field in ipairs(spec) do
				self:printField(field)
			end
		end,
		-- Returns a dissector function containing the basic while loop that callback
		-- the parseFunction. Can handle TCP reassembly.
		getDissector = function(self, parseFunction)
			local dissector = function(buffer, pinfo, tree)
				local bytesConsumed = 0
					
				while (bytesConsumed < buffer:len()) do		
					local msgLength = parseFunction(buffer(bytesConsumed), pinfo, tree)
					if msgLength > 0 then
						bytesConsumed = bytesConsumed + msgLength
					elseif msgLength == 0 then
						return 0
					else
						self:trace('Frame: ' .. pinfo.number, 
							  'Incomplete message.', 
							  'bytesConsumed:' .. bytesConsumed,
							  'missing:' .. msgLength)
						-- we need more bytes, so set the desegment_offset to what we
						-- already consumed, and the desegment_len to how many more
						-- are needed
						pinfo.desegment_offset = bytesConsumed
						-- invert the negative result so it's a positive number
						pinfo.desegment_len = - msgLength
						return
					end
				end
			end
			return dissector
		end,
		-- Enables the protocol. Uses protocol preferences
		enableDissector = function(self, transportProtocol)
			self:trace('enabling dissector')			
			local tcp_port = DissectorTable.get('tcp.port')			
			tcp_port:add(self.protocol.prefs.ports, self.protocol)
		end,
		-- Disables the protocol.
		disableDissector = function(self)
			self:trace('disabling dissector')			
			local tcp_port = DissectorTable.get('tcp.port')
			tcp_port:remove_all(self.protocol)
		end,
		-- Set the default preferences for the protocol.
		setDefaultPreference = function(self, defaultPrefs)
			assert(defaultPrefs, 'defaultPrefs cannot be nil')
			
			self.protocol.prefs.ports = Pref.range('Ports', 
											  defaultPrefs.ports,
											  'Port range (i.e. 7001-70010,8005,8100)',
											  65535)
			self.protocol.prefs.trace = Pref.bool('Trace', 
											 defaultPrefs.trace,
											 'Enable trace messages.')
											 
			self.protocol.prefs_changed = function()
				self:disableDissector()
				self:enableDissector()
			end
		end,
		-- Create a parser function for specific message spec.
		createParser = function(self, fieldsSpec)
			assert(fieldsSpec, 'fieldsSpec cannot be nil')
			
			return function(buf, pkt, root)
				local bytesConsumed = 0
				
				local subtree = root:add(self.protocol, 
										 buf(), 
										 self.protocol.name .. ' Protocol')

				for i, field in ipairs(fieldsSpec) do		
					if field.type then
						if (field.type == 'FIXED') and (field:valueSingle(buf, bytesConsumed) ~= field.fixedValue) then
							self:trace('invalid fixed value')
							return 0
						end				
						local fieldLen = field:add_to(subtree, buf, bytesConsumed)				
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
				specs[v.name] = readMsgSpec(dir .. v.file, 
									   columns,									   
									   string.lower(self.protocol.name).. '.',
									   offset,
									   sep)
				self:printMsgSpec(specs[v.name])		
				msgSpecs[v.name] = msgSpecToFieldSpec(v.name, v.name .. ' message', specs[v.name], header, trailer)
				self:printFieldSpec(msgSpecs[v.name])				
				msgParsers[v.name] = self:createParser(msgSpecs[v.name])				
			end

			for i, f in pairs(Field.repo) do				
				self:trace('Adding ' .. i .. ' to proto.fields')
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
		end
	}
end

return {
	Field = Field, 
	readMsgSpec = readMsgSpec, 
	msgSpecToFieldSpec = msgSpecToFieldSpec, 
	createProtoHelper = createProtoHelper
}