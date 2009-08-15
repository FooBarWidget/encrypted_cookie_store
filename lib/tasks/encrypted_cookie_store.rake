dir = File.expand_path(File.join(File.dirname(__FILE__), ".."))
$LOAD_PATH << dir

namespace :secret do
	desc "Generate an encryption key for EncryptedCookieStore that's cryptographically secure."
	task :encryption_key do
		require 'encrypted_cookie_store/constants'
		puts ActiveSupport::SecureRandom.hex(EncryptedCookieStoreConstants::ENCRYPTION_KEY_SIZE)
	end
end