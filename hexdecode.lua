local function hexdecode(hex)
	return (hex:gsub("%x%x", function(n) 
		return string.char(tonumber(n, 16)) 
	end))
end

local args = { ... }
print(hexdecode(args[1]))
