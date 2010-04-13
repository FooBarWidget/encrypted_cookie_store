require 'openssl'
require 'encrypted_cookie_store/constants'

class EncryptedCookieStore < ActionController::Session::CookieStore
	OpenSSLCipherError = OpenSSL::Cipher.const_defined?(:CipherError) ? OpenSSL::Cipher::CipherError : OpenSSL::CipherError
	include EncryptedCookieStoreConstants
	
	class << self
		attr_accessor :iv_cipher_type
		attr_accessor :data_cipher_type
	end
	
	self.iv_cipher_type   = "aes-128-ecb".freeze
	self.data_cipher_type = "aes-256-cfb".freeze
	
	def initialize(app, options = {})
		ensure_encryption_key_secure(options[:encryption_key])
		@encryption_key = unhex(options[:encryption_key]).freeze
		@iv_cipher      = OpenSSL::Cipher::Cipher.new(EncryptedCookieStore.iv_cipher_type)
		@data_cipher    = OpenSSL::Cipher::Cipher.new(EncryptedCookieStore.data_cipher_type)
		super(app, options)
	end
	
private
	# Like ActiveSupport::MessageVerifier, but does not base64-encode data.
	class MessageVerifier
		def initialize(secret, digest = 'SHA1')
			@secret = secret
			@digest = digest
		end
		
		def verify(signed_message)
			digest, data = signed_message.split("--", 2)
			if digest != generate_digest(data)
				raise ActiveSupport::MessageVerifier::InvalidSignature
			else
				Marshal.load(data)
			end
		end
		
		def generate(value)
			data   = Marshal.dump(value)
			digest = generate_digest(data)
			"#{digest}--#{data}"
		end
		
	private
		def generate_digest(data)
			OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new(@digest), @secret, data)
		end
	end
	
	def marshal(session)
		# We hmac-then-encrypt instead of encrypt-then-hmac so that we
		# can properly detect:
		# - changes to the encryption key or initialization vector
		# - a migration from the unencrypted CookieStore.
		#
		# Being able to detect these allows us to invalidate the old session data.
		
		@iv_cipher.encrypt
		@data_cipher.encrypt
		@iv_cipher.key   = @encryption_key
		@data_cipher.key = @encryption_key
		
		session_data     = super(session)
		iv               = @data_cipher.random_iv
		@data_cipher.iv  = iv
		encrypted_iv     = @iv_cipher.update(iv) << @iv_cipher.final
		encrypted_session_data = @data_cipher.update(session_data) << @data_cipher.final
		
		"#{base64(encrypted_iv)}--#{base64(encrypted_session_data)}"
	end
	
	def unmarshal(cookie)
		if cookie
			b64_encrypted_iv, b64_encrypted_session_data = cookie.split("--", 2)
			if b64_encrypted_iv && b64_encrypted_session_data
				encrypted_iv           = ActiveSupport::Base64.decode64(b64_encrypted_iv)
				encrypted_session_data = ActiveSupport::Base64.decode64(b64_encrypted_session_data)
				
				@iv_cipher.decrypt
				@iv_cipher.key = @encryption_key
				iv = @iv_cipher.update(encrypted_iv) << @iv_cipher.final
				
				@data_cipher.decrypt
				@data_cipher.key = @encryption_key
				@data_cipher.iv = iv
				session_data = @data_cipher.update(encrypted_session_data) << @data_cipher.final
				super(session_data)
			end
		else
			nil
		end
	rescue OpenSSLCipherError
		nil
	end
	
	# To prevent users from using an insecure encryption key like "Password" we make sure that the
	# encryption key they've provided is at least 30 characters in length.
        def ensure_encryption_key_secure(encryption_key)
		if encryption_key.blank?
			raise ArgumentError, "An encryption key is required for encrypting the " +
				"cookie session data. Please set config.action_controller.session = { " +
				"..., :encryption_key => \"some random string of exactly " +
				"#{ENCRYPTION_KEY_SIZE * 2} bytes\", ... } in config/environment.rb"
		end
		
		if encryption_key.size != ENCRYPTION_KEY_SIZE * 2
			raise ArgumentError, "The EncryptedCookieStore encryption key must be a " +
				"hexadecimal string of exactly #{ENCRYPTION_KEY_SIZE * 2} bytes. " +
				"The value that you've provided, \"#{encryption_key}\", is " +
				"#{encryption_key.size} bytes. You could use the following (randomly " +
				"generated) string as encryption key: " +
				ActiveSupport::SecureRandom.hex(ENCRYPTION_KEY_SIZE)
		end
	end
	
	def verifier_for(secret, digest)
		key = secret.respond_to?(:call) ? secret.call : secret
		MessageVerifier.new(key, digest)
	end
	
	def base64(data)
		ActiveSupport::Base64.encode64s(data)
	end
	
	def unhex(hex_data)
		[hex_data].pack("H*")
	end
end