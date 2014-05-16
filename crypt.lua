------------------------------------------------------------------
-- Project: Crypt 												--
--																--
-- Description: Crypt allows you to store data permanently 		--
--				and fully encrypted so it's out of the way 		--
--				of prying eyes.									--
--																--
-- Requirements: OpenSSL plugin from Corona Labs.				--
--																--
-- File name: crypt.lua											--
--																--
-- Creation Date: May 09, 2014									--
--																--
-- Copyright (C) 2014 Graham Ranson. All rights reserved.		--
--																--
------------------------------------------------------------------

-- Main class table
local Crypt = {}
local Crypt_mt = { __index = Crypt }

-- Required libraries
local openssl = require( "plugin.openssl" )
local json = require( "json" )
local mime = require( "mime" )
local lfs = require( "lfs" )
local crypto = require( "crypto" )

-- Localised functions
local encode = json.encode
local decode = json.decode
local b64 = mime.b64
local unb64 = mime.unb64
local open = io.open
local close = io.close
local pathForFile = system.pathForFile
local remove = os.remove
local attributes = lfs.attributes
local digest = crypto.digest
local tostring = tostring
local type = type
local pairs = pairs
local print = print

-- Localised variables
local DocumentsDirectory = system.DocumentsDirectory
local sha512 = crypto.sha512

-- Class values
local _version = 0.2

------------------
--	CONSTRUCTOR --
------------------

--- Initiates a new Crypt object.
-- @param name The name of the crypt.
-- @param key Key used for encryption / decryption. It gets hashed internally and is never stored anywhere. Feel free to hash it yourself as well if you like.
-- @param algorithm Algorithm used for encryption / decryption. Optional, defaults to 'aes-256-ecb'.
-- @return The new object.
function Crypt:new( name, key, algorithm )

	local self = {}

	setmetatable( self, Crypt_mt )

	-- If the crypt doesn't have a name then it can't be created.
	if not name then
		self:_error( "No name specified on creation." )
		return nil
	end

	-- If no key is specified then the crypt can't be encrypted/decrypted.
	if not key then
		self:_error( "No key specified on creation." )
		return nil
	end

	-- If the OpenSSL plugin can't be found then no encryption/decryption can take place.
	if not openssl then
		self:_error( "OpenSSL plugin not found." )
		return nil
	end

	-- Private values
	self._name = name
	self._extension = "crypt"
	self._algorithm = algorithm or "aes-256-ecb"
	self._filename = self._name .. "." .. self:getExtension()
	self._path = pathForFile( self:getFilename(), DocumentsDirectory )
	self._key = digest( sha512, key )
	self._cipher = openssl.get_cipher( self._algorithm )
	self._data = {}

	-- If the file doesn't exist then this is the first time it has been created so call the private onCreate function to create the header.
	if not self:_exists() then
		self:_onCreate()
	end

	-- Register the handler for 'system' events.
	Runtime:addEventListener( "system", self )

    return self
    
end

-----------------------
--	PUBLIC FUNCTIONS --
-----------------------

--- Gets a piece of data.
-- @param name The name of the data.
-- @return The data.
function Crypt:get( name )

	-- Call the private onAccess function to update the header.
	if name ~= "_header" then
		self:_onAccess()
	end

	return self._data[ tostring( name ) ]

end

--- Sets a piece of data.
-- @param name The name of the data.
-- @param value The value to set.
function Crypt:set( name, value )
	
	-- Call the private onModify function to update the header.
	if name ~= "_header" then
		self:_onModify()
	end

	self._data[ tostring( name ) ] = value

end

--- Sets a piece of data if it isn't already set.
-- @param name The name of the data.
-- @param value The value to set.
function Crypt:setIfNew( name, value )
	if not self:isSet( name ) then
		self:set( name, value )
		return true
	end
	return false
end

--- Sets a piece of data if it's either higher than the current value or if the data doesn't exist.
-- @param name The name of the data.
-- @param value The value to set.
function Crypt:setIfHigher( name, value )
	if not self:isSet( name ) or self:get( name ) < value then
		self:set( name, value )
	end
end

--- Sets a piece of data if it's either lower than the current value or if the data doesn't exist.
-- @param name The name of the data.
-- @param value The value to set.
function Crypt:setIfLower( name, value )
	if not self:isSet( name ) or self:get( name ) > value then
		self:set( name, value )
	end
end

--- Increments a piece of data if it exists.
-- @param name The name of the data.
-- @param amount The amount to increment. Optional, defaults to 1.
function Crypt:increment( name, amount )
	if self:isSet( name ) then
		if self:getType( name ) == "number" then
			self:set( name, self:get( name ) + ( amount or 1 ) )
		else
			self:_warning( "Data named " .. name .. " is not a 'number', can't perform increment." );
		end		
	else
		self:_warning( "No data named " .. name .. ", can't perform increment." );
	end
end

--- Decrements a piece of data if it exists.
-- @param name The name of the data.
-- @param amount The amount to decrement. Optional, defaults to 1.
function Crypt:decrement( name, value )
	if self:isSet( name ) then
		if self:getType( name ) == "number" then
			self:set( name, self:get( name ) - ( amount or 1 ) )
		else
			self:_warning( "Data named " .. name .. " is not a 'number', can't perform increment." );
		end	
	else
		self:_warning( "No data named " .. name .. ", can't perform decrement." );
	end
end

--- Checks if a piece of data is set on this crypt.
-- @param name The name of the data.
-- @return True if the data exists, false otherwise.
function Crypt:isSet( name )
	return self:get( name ) ~= nil and true or false
end

--- Gets the type of a saved piece of data.
-- @param name The name of the data.
-- @return The type the data is. Nil if no data found.
function Crypt:getType( name )
	if self:isSet( name ) then
		return type( self:get( name ) )
	else
		return nil
	end
end


--- Loads data from disk and decrypts it.
function Crypt:load()

	-- Open the file for reading.
	local file = open( self._path, "r" )

	if file then
	
		-- Read in the data and close the file.
		local data = file:read( "*a" )

		close( file )
		file = nil

		if data then
			
			-- Remove the base 64 encoding.
			data = unb64( data )

			-- If we have a cipher then decrypt the data using the hashed key.
			if self._cipher then
				data = self._cipher:decrypt( data, self._key )
			end

			-- Json decode the data.
			self._data = decode( data )

			-- Load the header table.
			self._header = self:get( "_header" )

			-- Finally call the private onLoad function to update the header.
			self:_onLoad()

		end

	else
		self:_error( "Can't open file for reading at path - " .. self._path .. " - if this crypt was just created then you can ignore this message." )
	end

end

--- Encrypts the data and saves it to disk.
function Crypt:save()

	-- Call the private onSave function to update the header.
	self:_onSave()

	-- Set the header table.
	self:set( "_header", self._header )

	-- Json encode the data.
	local data = encode( self._data )

	-- If we have a cipher then encrypt the data with the hashed key.
	if self._cipher then
		data = self._cipher:encrypt( data, self._key )
	end

	-- Base 64 encode the encrypted data.
	data = b64( data )

	-- Open the file for writing.
	local file = open( self._path, "w" )

	-- Save out the data and close the file.
	if file then
		file:write( data )
		close( file )
		file = nil
	else
		self:_error( "Can't open file for writing at path - " .. self._path )
	end

end

--- Clears all data from this crypt and saves it.
function Crypt:clear()
	self._data = {}
	self:save()
end

-- Clears all data from this crypt and then deletes the file.
function Crypt:wipe()
	self:clear()
	remove( self._path )
end

--- Gets the header table for this crypt.
-- @return The header table.
function Crypt:getHeader()
	return self._header
end

--- Updates the version of this crypt to the current version number.
function Crypt:updateVersion()
	self._header.version = _version
end

--- Sets the iCloud automatic backup flag for this crypt on Mac OS X and iOS systems.
-- @param sync True if you'd like it to get backed up, false otherwise.
-- @return True if it was successful and false if not. Nil on Android and Windows. If false then an error string is returned as the second paramater.
function Crypt:setSync( sync )
	return native.setSync( self:getFilename(), { iCloudBackup = sync } ) 
end

--- Gets the filename of the crypt. Useful if you want to do anything with the file such as upload it. All crypts are located in system.DocumentsDirectory.
-- @return The filename of the crypt.
function Crypt:getFilename()
	return self._filename
end

--- Gets the full path to the crypt. Useful if you want to do anything with the file such as upload it.
-- @return The path to the crypt file.
function Crypt:getPath()
	return self._path
end

--- Gets the extension of the crypt file.
-- @return The extension of the crypt file.
function Crypt:getExtension()
	return self._extension
end

-- Deletes the data values from memory.
function Crypt:destroy()

	-- Remove the 'system' event listener.
	Runtime:removeEventListener( "system", self )

	-- Nil out the data first
	self._data = nil

	-- Then nil out all values.
	for k, v in pairs( self ) do
		self[ k ] = nil
	end

end

------------------------
--	PRIVATE FUNCTIONS --
------------------------

-- Displays an error to the command line.
-- @param message The message to display.
function Crypt:_error( message )
	print( "Crypt Error: " .. message )
end

-- Displays a warning to the command line.
-- @param message The message to display.
function Crypt:_warning( message )
	print( "Crypt Warning: " .. message )
end

--- Checks if the crypt file exists.
-- @return True if it exists, false otherwise.
function Crypt:_exists()
	return attributes( self._path, "mode" ) == "file"
end

-- Called when the crypt is first created, sets the _header.created, and _header.version values.
function Crypt:_onCreate()
	self._header = self._header or {}
	self._header.version = self._header.version or _version
	self._header.created = self._header.created or os.time()
end

-- Called when crypt is saved, updates the _header.saved value.
function Crypt:_onSave()
	self._header = self._header or {}
	self._header.saved = os.time()
end

-- Called when crypt is loaded, updates the _header.loaded value.
function Crypt:_onLoad()
	self._header = self._header or {}
	self._header.loaded = os.time()
end

-- Called when a piece of data is retrieved, updates the _header.accessed value.
function Crypt:_onAccess()
	self._header = self._header or {}
	self._header.accessed = os.time()
end

-- Called when a piece of data is stored, updates the _header.modified value.
function Crypt:_onModify()
	self._header = self._header or {}
	self._header.modified = os.time()
end

---------------------
--	EVENT HANDLERS --
---------------------

-- Event handler for the 'system' event.
-- @param event The event paramaters.
function Crypt:system( event )

	local type = event.type

	if type == "applicationSuspend" then
		self:save()
	elseif type == "applicationResume" then

	elseif type == "applicationExit" then
		self:save()
	elseif type == "applicationStart" then

	end
 
end

-- Return the class table.
return Crypt