require 'openssl'
require 'zlib'

require 'active_support/core_ext/object/deep_dup'
require 'active_support/core_ext/numeric/time'
require 'action_dispatch'

module ActionDispatch
  module Session
    class EncryptedCookieStore < CookieStore
      class << self
        attr_accessor :data_cipher_type
      end
      self.data_cipher_type = "aes-128-cbc".freeze

      SESSION_KEY = if Rack.release >= '2'
                      Rack::RACK_SESSION
                    else
                      Rack::Session::Abstract::ENV_SESSION_KEY
                    end

      def initialize(app, options = {})
        @logger = options.delete(:logger)
        @digest = options.delete(:digest) || 'SHA1'

        @compress = options[:compress]
        @compress = true if @compress.nil?

        @secret = options.delete(:secret)
        @secret = @secret.call if @secret.respond_to?(:call)
        @secret.freeze

        @data_cipher = OpenSSL::Cipher.new(EncryptedCookieStore.data_cipher_type)
        @encryption_key = unhex(@secret[0...(@data_cipher.key_len * 2)]).freeze
        ensure_encryption_key_secure
        options[:refresh_interval] ||= 5.minutes

        super(app, options)
      end

      if Rack.release >= '2'
        def get_header(req, key)
          req.get_header(key)
        end

        def fetch_header(req, key, &block)
          req.fetch_header(key, &block)
        end

        def set_header(req, key, value)
          req.set_header(key, value)
        end

        # overrides method in ActionDispatch::Session::CookieStore
        def cookie_jar(request)
          request.cookie_jar
        end

        write_session = 'write_session'
      else
        def get_header(env, key)
          env[key]
        end

        def fetch_header(env, key, &block)
          env.fetch(key, &block)
        end

        def set_header(env, key, value)
          env[key] = value
        end

        # overrides method in ActionDispatch::Session::CookieStore
        def cookie_jar(env)
          request = ActionDispatch::Request.new(env)
          request.cookie_jar
        end

        write_session = 'set_session'
      end

      # overrides method in Rack::Session::Cookie
      def load_session(req)
        if time = timestamp(req)
          fetch_header(req, 'encrypted_cookie_store.session_refreshed_at') { |k| set_header(req, k, Time.at(time).utc) }
        end
        super
      end

      private

      # overrides method in ActionDispatch::Session::CookieStore
      def unpacked_cookie_data(req)
        fetch_header(req, "action_dispatch.request.unsigned_session_cookie") do |k|
          v = stale_session_check! do
            if data = unmarshal(get_cookie(req), get_header(req, SESSION_KEY).options)
              data.stringify_keys!
            end
            data ||= {}
            set_header(req, 'encrypted_cookie_store.original_cookie', data.deep_dup.except('timestamp'))
            data
          end
          set_header(req, k, v)
        end
      end

      # overrides method in ActionDispatch::Session::CookieStore
      class_eval <<-RUBY, __FILE__, __LINE__ + 1
        def #{write_session}(req, sid, session_data, options)
          session_data = super
          if session_data.is_a?(::ActionDispatch::Session::CookieStore::SessionId)
            session_id = session_data
            session_data = session_data.cookie_value
            session_data.delete('timestamp')
            session_id.instance_variable_set(:@cookie_value, marshal(session_data, options)) # swap out the cookie value
            session_id
          else
            session_data.delete('timestamp')
            marshal(session_data, options)
          end
        end
      RUBY

      # overrides method in Rack::Session::Abstract::ID
      def commit_session?(req, session, options)
        can_commit = super
        can_commit && (session_changed?(req, session) || refresh_session?(req, options))
      end

      def timestamp(req)
        unpacked_cookie_data(req)["timestamp"]
      end

      def session_changed?(req, session)
        (session || {}).to_hash.stringify_keys.except('timestamp') != (get_header(req, 'encrypted_cookie_store.original_cookie') || {})
      end

      def refresh_session?(req, options)
        if options[:expire_after] && options[:refresh_interval] && time = timestamp(req)
          Time.now.utc.to_i > time + options[:refresh_interval].to_i
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
        timestamp        = Time.now.utc.to_i if options[:expire_after]
        digest           = hmac_digest(iv, session_data, timestamp)

        result = "#{base64(iv)}#{compressed_session_data == session_data ? '.' : ' '}#{base64(encrypted_session_data)}.#{base64(digest)}"
        result << ".#{base64([timestamp].pack('N'))}" if options[:expire_after]
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
          return nil unless digest == hmac_digest(iv, session_data, timestamp)
          if options[:expire_after]
            return nil unless timestamp && Time.now.utc.to_i <= timestamp + options[:expire_after].to_i
          end

          loaded_data = nil
          begin
            loaded_data = Marshal.load(session_data)
          rescue
            @logger.error("Could not unmarshal session_data: #{session_data.inspect}") if @logger
          end

          loaded_data['timestamp'] = timestamp if loaded_data && timestamp
          loaded_data
        else
          nil
        end
      rescue Zlib::DataError, OpenSSL::Cipher::CipherError
        nil
      end

      # To prevent users from using an insecure encryption key like "Password" we make sure that the
      # encryption key they've provided is at least 30 characters in length.
      def ensure_encryption_key_secure
        if @secret.blank?
          raise ArgumentError, "An encryption key is required for encrypting the " +
              "cookie session data. Please set config.action_controller.session = { " +
              "..., :secret => \"some random hex string of at least " +
              "#{@data_cipher.key_len} bytes\", ... } in config/environment.rb"
        end

        if @secret.size < @data_cipher.key_len * 2
          raise ArgumentError, "The EncryptedCookieStore encryption key must be a " +
              "hexadecimal string of at least #{@data_cipher.key_len} bytes. " +
              "The value that you've provided, \"#{@secret}\", is " +
              "#{@secret.size / 2} bytes. You could use the following (randomly " +
              "generated) string as the secret: " +
              SecureRandom.hex(@data_cipher.key_len)
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

      def hmac_digest(iv, session_data, timestamp)
        hmac_body = session_data + timestamp.to_s
        hmac_body = iv + hmac_body if iv
        OpenSSL::HMAC.digest(OpenSSL::Digest.new(@digest), @secret, hmac_body)
      end
    end
  end
end

EncryptedCookieStore = ActionDispatch::Session::EncryptedCookieStore
