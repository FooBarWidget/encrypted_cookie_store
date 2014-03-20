require 'openssl'
require 'zlib'

require 'active_support/core_ext/hash/deep_dup'
require 'active_support/core_ext/numeric/time'
require 'action_dispatch'

module ActionDispatch
  module Session
    class EncryptedCookieStore < CookieStore
      class << self
        attr_accessor :data_cipher_type
      end
      self.data_cipher_type = "aes-128-cbc".freeze

      EXPIRE_AFTER_KEY = "encrypted_cookie_store.session_expire_after"

      OpenSSLCipherError = OpenSSL::Cipher.const_defined?(:CipherError) ? OpenSSL::Cipher::CipherError : OpenSSL::CipherError

      def initialize(app, options = {})
        @digest = options.delete(:digest) || 'SHA1'

        @compress = options[:compress]
        @compress = true if @compress.nil?

        @secret = options.delete(:secret)
        @secret = @secret.call if @secret.respond_to?(:call)
        @secret.freeze
        @encryption_key = unhex(@secret).freeze
        ensure_encryption_key_secure

        @data_cipher = OpenSSL::Cipher::Cipher.new(EncryptedCookieStore.data_cipher_type)
        options[:refresh_interval] ||= 5.minutes

        super(app, options)
      end

      def call(env)
        @expire_after = env[EXPIRE_AFTER_KEY]
        super
      end

      private

      def expire_after(options={})
        @expire_after || options[:expire_after]
      end

      # overrides method in ActionDispatch::Session::CookieStore
      def unpacked_cookie_data(env)
        env['encrypted_cookie_store.cookie'] ||= begin
          stale_session_check! do
            request = ActionDispatch::Request.new(env)
            if data = unmarshal(request.cookie_jar[@key])
              data.stringify_keys!
            end
            data ||= {}
            env['encrypted_cookie_store.original_cookie'] = data.deep_dup.except(:timestamp)
            data
          end
        end
      end

      # overrides method in ActionDispatch::Session::CookieStore
      def set_cookie(env, session_id, cookie)
        request = ActionDispatch::Request.new(env)
        request.cookie_jar[@key] = cookie
      end

      # overrides method in ActionDispatch::Session::CookieStore
      def set_session(env, sid, session_data, options)
        session_data = super
        session_data.delete(:timestamp)
        marshal(session_data, options)
      end

      # overrides method in Rack::Session::Cookie
      def load_session(env)
        if time = timestamp(env)
          env['encrypted_cookie_store.session_refreshed_at'] ||= Time.at(time).utc
        end
        super
      end

      # overrides method in Rack::Session::Abstract::ID
      def commit_session?(env, session, options)
        can_commit = super
        can_commit && (session_changed?(env, session) || refresh_session?(env, options))
      end


      def timestamp(env)
        unpacked_cookie_data(env)["timestamp"]
      end

      def session_changed?(env, session)
        (session || {}).to_hash.stringify_keys.except(:timestamp) != (env['encrypted_cookie_store.original_cookie'] || {})
      end

      def refresh_session?(env, options)
        if expire_after(options) && options[:refresh_interval] && time = timestamp(env)
          Time.now.utc.to_i > time + options[:refresh_interval]
        else
          false
        end
      end

      def marshal(data, options={})
        @data_cipher.encrypt
        @data_cipher.key = @encryption_key

        session_data     = Marshal.dump(data)
        iv               = @data_cipher.random_iv
        if @compress
          compressed_session_data = deflate(session_data, 5)
          compressed_session_data = session_data if compressed_session_data.length >= session_data.length
        else
          compressed_session_data = session_data
        end
        encrypted_session_data = @data_cipher.update(compressed_session_data) << @data_cipher.final
        timestamp        = Time.now.utc.to_i if expire_after(options)
        digest           = OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new(@digest), @secret, session_data + timestamp.to_s)

        result = "#{base64(iv)}#{compressed_session_data == session_data ? '.' : ' '}#{base64(encrypted_session_data)}.#{base64(digest)}"
        result << ".#{base64([timestamp].pack('N'))}" if expire_after(options)
        result
      end

      def unmarshal(data, options={})
        return nil unless data
        compressed = !!data.index(' ')
        b64_iv, b64_encrypted_session_data, b64_digest, b64_timestamp = data.split(/\.| /, 4)
        if b64_iv && b64_encrypted_session_data && b64_digest
          iv                     = unbase64(b64_iv)
          encrypted_session_data = unbase64(b64_encrypted_session_data)
          digest                 = unbase64(b64_digest)
          timestamp              = unbase64(b64_timestamp).unpack('N').first if b64_timestamp

          @data_cipher.decrypt
          @data_cipher.key = @encryption_key
          @data_cipher.iv = iv
          session_data = @data_cipher.update(encrypted_session_data) << @data_cipher.final
          session_data = inflate(session_data) if compressed
          return nil unless digest == OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new(@digest), @secret, session_data + timestamp.to_s)
          if expire_after(options)
            return nil unless timestamp && Time.now.utc.to_i <= timestamp + expire_after(options)
          end

          loaded_data = Marshal.load(session_data) || nil
          loaded_data[:timestamp] = timestamp if loaded_data && timestamp
          loaded_data
        else
          nil
        end
      rescue Zlib::DataError, OpenSSLCipherError
        nil
      end

      # To prevent users from using an insecure encryption key like "Password" we make sure that the
      # encryption key they've provided is at least 30 characters in length.
      def ensure_encryption_key_secure
        if @encryption_key.blank?
          raise ArgumentError, "An encryption key is required for encrypting the " +
              "cookie session data. Please set config.action_controller.session = { " +
              "..., :encryption_key => \"some random string of at least " +
              "16 bytes\", ... } in config/environment.rb"
        end

        if @encryption_key.size < 16 * 2
          raise ArgumentError, "The EncryptedCookieStore encryption key must be a " +
              "hexadecimal string of at least 16 bytes. " +
              "The value that you've provided, \"#{@encryption_key}\", is " +
              "#{@encryption_key.size / 2} bytes. You could use the following (randomly " +
              "generated) string as encryption key: " +
              ActiveSupport::SecureRandom.hex(16)
        end
      end

      def base64(data)
        ::Base64.encode64(data).tr('+/', '-_').gsub(/=|\n/, '')
      end

      def unbase64(data)
        ::Base64.decode64(data.tr('-_', '+/').ljust((data.length + 4 - 1) / 4 * 4, '='))
      end

      # compress
      def deflate(string, level)
        z = Zlib::Deflate.new(level)
        dst = z.deflate(string, Zlib::FINISH)
        z.close
        dst
      end

      # decompress
      def inflate(string)
        zstream = Zlib::Inflate.new
        buf = zstream.inflate(string)
        zstream.finish
        zstream.close
        buf
      end

      def unhex(hex_data)
        [hex_data].pack("H*")
      end
    end
  end
end

EncryptedCookieStore = ActionDispatch::Session::EncryptedCookieStore
