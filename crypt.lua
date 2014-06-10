------------------------------------------------------------------
-- Project: Crypt 												--
--																--
-- Description: Crypt allows you to store data permanently 		--
--				and fully encrypted so it's out of the way 		--
--				of prying eyes.	If you wish to not use 			--
--				encryption then don't include the OpenSSL 		--
--				plugin.											--
--																--
-- Requirements: OpenSSL plugin from Corona Labs.				--
--																--
-- File name: crypt.lua											--
--																--
-- Creation Date: May 09, 2014									--
--																--
-- Email: graham@grahamranson.co.uk								--
--																--
-- Twitter: @GrahamRanson										--
--																--
-- Website: www.grahamranson.co.uk								--
--																--
-- Copyright (C) 2014 Graham Ranson. All rights reserved.		--
--																--
------------------------------------------------------------------

-- Main class table
local Crypt = {}
local Crypt_mt = { __index = Crypt }

-- Overridden functions
local _require = require
local require = function( name )
	local lib
	pcall( function() lib = _require( name ) end )
	return lib
end

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
local extension = "crypt"
local defaultAlgorithm = "aes-256-ecb"

------------------
--	CONSTRUCTOR --
------------------

--- Initiates a new Crypt object.
-- @param name The name of the crypt.
-- @param algorithm Algorithm used for encryption / decryption. Optional, defaults to 'aes-256-ecb'.
-- @return The new object or nil if there was an issue.
function Crypt:new( name, key, algorithm )

	local self = {}

	setmetatable( self, Crypt_mt )

	-- If the crypt doesn't have a name then it can't be created.
	if not name then
		self:_error( "No name specified on creation." )
		return nil
	end

	-- If the OpenSSL plugin can't be found then no encryption/decryption can take place.
	if not openssl then
		self:_warning( "OpenSSL plugin not found. Encryption and decryption can not take place." )
	end

	-- Private values
	self._name = name
	self._algorithm = algorithm or defaultAlgorithm
	self._filename = self._name .. "." .. self:getExtension()
	self._path = pathForFile( self:getFilename(), DocumentsDirectory )

	if openssl and type( openssl ) ~= "boolean" then
		self._cipher = openssl.get_cipher( self._algorithm )	
	end

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

	if self._data then
		return self._data[ tostring( name ) ]
	end
	
end

--- Sets a piece of data.
-- @param name The name of the data.
-- @param value The value to set.
function Crypt:set( name, value )
	
	-- Call the private onModify function to update the header.
	if name ~= "_header" then
		self:_onModify()
	end

	if self._data then
		self._data[ tostring( name ) ] = value
	end

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
-- @param key Key used for encryption / decryption. It gets hashed internally and is never stored physically. Feel free to hash it yourself as well if you like.
-- @return True if the decryption worked, false otherwise.
function Crypt:load( key )

	if openssl then
	
		-- If no key is specified then the crypt can't be encrypted/decrypted.
		self:_checkKey( key, "load" )

		-- If a blank key is specified then the crypt can't be encrypted/decrypted.
		if key == "" then
			self:_error( "Blank key specified on load." )
			return nil
		end
		
		-- Hash and remember the key
		self:setKey( key )

	end

	-- If the file exists then we need to load it up and decrupt it
	if self:_exists() then

		-- Read in the data and close the file.
		local data = self:_readFile()

		-- If we have a cipher then decrypt the data using the hashed key.
		data = self:_decryptData( data )
		
		-- Json decode the data.
		self._data = decode( data )

		if self._data then

			-- Load the header table.
			self._header = self:get( "_header" )

			-- Finally call the private onLoad function to update the header.
			self:_onLoad()
			
			return true

		end


	else -- If no file exists then create an empty data table

		-- The data table
		self._data = {}

		-- Load the header table.
		self._header = self:get( "_header" )

		-- Finally call the private onLoad function to update the header.
		self:_onLoad()

		-- Display a warning about the file not existing
		self:_warning( "Can't open file for reading at path - " .. self._path .. " - if this crypt was just created then you can ignore this message." )
	
		return true

	end
	
	return false

end

--- Encrypts the data and saves it to disk.
function Crypt:save()

	-- Call the private onSave function to update the header.
	self:_onSave()

	-- Set the header table.
	self:set( "_header", self._header )

	-- Write the data to disk.
	self:_writeFile()

end

--- Checks if a key will decrypt the current data.
-- @param key The key to check with.
-- @return True if the key will decrypt the data, false otherwise.
function Crypt:verifyKey( key )

	-- If no key is specified then the crypt can't be encrypted/decrypted.
	self:_checkKey( key, "verifyKey" )

	-- First read in the encrypted data.
	local data = self:_readFile()

	-- If there is data...
	if data then

		-- ... then try to decrypt it.
		data = self:_decryptData( data, key )

		-- If there is still data than the decryption worked.
		if data then

			-- Now decode the data, if this works then we know it's all good.
			data = decode( data )

			if data then
				return true
			end
		end
	
	end

	return false

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
	return extension
end

--- Sets the key used for encryption / decryption.
-- @param key Key used for encryption / decryption. It gets hashed internally and is never stored physically. Feel free to hash it yourself as well if you like.
function Crypt:setKey( key )
	self._key = key and self:_hash( key ) or self._key
end

--- Checks if the crypt file exists.
-- @return True if it exists, false otherwise.
function Crypt:exists( name )
	local path = pathForFile( name .. "." .. self:getExtension(), DocumentsDirectory )
	return attributes( path, "mode" ) == "file"
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

-- Read in the contents of the crypt file.
-- @return The read in data.
function Crypt:_readFile()

	-- Open the file for reading.
	local file = open( self._path, "r" )

	-- If the file exists then we need to load it up and decrypt it
	if file then
		
		-- Read in the data and close the file.
		local data = file:read( "*a" )

		close( file )
		file = nil

		if data then
			
			-- Remove the base 64 encoding.
			data = unb64( data )

			-- Return the data
			return data

		end

	end	

end

-- Write the current data to the crypt file.
function Crypt:_writeFile()

	-- Json encode the data.
	local data = encode( self._data )

	-- If we have a cipher then encrypt the data with the hashed key.
	data = self:_encryptData( data )

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

-- Decrypt some data.
-- @param data The data to decrypt.
-- @return The decrypted data.
function Crypt:_decryptData( data, key )
	if self._cipher then
		return self._cipher:decrypt( data, self._key or self:_hash( key ) )
	else
		return data
	end
end

-- Encrypt some data.
-- @param data The data to encrypt.
function Crypt:_encryptData( data )
	if self._cipher then
		return self._cipher:encrypt( data, self._key )
	else
		return data
	end
end

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
-- @param path The path to the ccrypt file. Optional, defaults to the path of this crypt file.
-- @return True if it exists, false otherwise.
function Crypt:_exists( path )
	return attributes( path or self._path, "mode" ) == "file"
end

--- Hashes key used for encryption / decryption.
-- @param key Key used for encryption / decryption. It gets hashed internally and is never stored physically. Feel free to hash it yourself as well if you like.
-- @return The hashed key.
function Crypt:_hash( key )
	return digest( sha512, key )
end

-- Called when the crypt is first created, sets the _header.created value.
function Crypt:_onCreate()
	self._header = self._header or {}
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

function Crypt:_checkKey( key, functionName )
	if not key then
		if openssl then
			self:_error( "No key specified during " .. functionName .. "." )
			return nil
		else
			self:_warning( "No key specified during " .. functionName .. " however no OpenSSL plugin was found so maybe you didn't want encryption?" )
		end
	end
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