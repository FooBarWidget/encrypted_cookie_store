require 'openssl'
require 'zlib'

class EncryptedCookieStore < ActionController::Session::CookieStore
  OpenSSLCipherError = OpenSSL::Cipher.const_defined?(:CipherError) ? OpenSSL::Cipher::CipherError : OpenSSL::CipherError

  class << self
    attr_accessor :data_cipher_type
  end

  self.data_cipher_type = "aes-128-cbc".freeze

  def initialize(app, options = {})
    options[:secret] = options[:secret].call if options[:secret].respond_to?(:call)
    ensure_encryption_key_secure(options[:secret])
    @encryption_key = unhex(options[:secret]).freeze
    @compress = options[:compress]
    @compress = true if @compress.nil?
    @data_cipher    = OpenSSL::Cipher::Cipher.new(EncryptedCookieStore.data_cipher_type)
    @options = options
    options[:refresh_interval] ||= 5.minutes
    super(app, options)
  end

  def call(env)
    prepare!(env)

    old_session_data, raw_old_session_data, old_timestamp = all_unpacked_cookie_data(env)
    # make sure we have a deep copy
    old_session_data = Marshal.load(raw_old_session_data) if raw_old_session_data
    env['encrypted_cookie_store.session_refreshed_at'] ||= session_refreshed_at(old_timestamp, env)

    status, headers, body = @app.call(env)

    session_data = env[ENV_SESSION_KEY]
    options = env[ENV_SESSION_OPTIONS_KEY]
    request = ActionController::Request.new(env)

    @options[:expire_after] = options[:expire_after] || @options[:expire_after]

    if !(options[:secure] && !request.ssl?) && (!session_data.is_a?(ActionController::Session::AbstractStore::SessionHash) || session_data.loaded? || options[:expire_after])
      session_data.send(:load!) if session_data.is_a?(ActionController::Session::AbstractStore::SessionHash) && !session_data.loaded?

      persistent_session_id!(session_data)

      old_session_data = nil if options[:expire_after] && old_timestamp && Time.now.utc.to_i > old_timestamp + options[:refresh_interval]
      return [status, headers, body] if session_data == old_session_data

      session_data = marshal(session_data.to_hash)

      raise CookieOverflow if session_data.size > MAX

      cookie = Hash.new
      cookie[:value] = session_data
      unless options[:expire_after].nil?
        cookie[:expires] = Time.now + options[:expire_after]
      end

      Rack::Utils.set_cookie_header!(headers, @key, cookie.merge(options))
    end

    [status, headers, body]
  end
private
  def secret
    @secret
  end

  def marshal(session)
    @data_cipher.encrypt
    @data_cipher.key = @encryption_key

    session_data     = Marshal.dump(session)
    iv               = @data_cipher.random_iv
    if @compress
      compressed_session_data = deflate(session_data, 5)
      compressed_session_data = session_data if compressed_session_data.length >= session_data.length
    else
      compressed_session_data = session_data
    end
    encrypted_session_data = @data_cipher.update(compressed_session_data) << @data_cipher.final
    timestamp        = Time.now.utc.to_i if @options[:expire_after]
    digest           = OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new(@digest), secret, session_data + timestamp.to_s)

    result = "#{base64(iv)}#{compressed_session_data == session_data ? '.' : ' '}#{base64(encrypted_session_data)}.#{base64(digest)}"
    result << ".#{base64([timestamp].pack('N'))}" if @options[:expire_after]
    result
  end

  def unmarshal(cookie)
    if cookie
      compressed = !!cookie.index(' ')
      b64_iv, b64_encrypted_session_data, b64_digest, b64_timestamp = cookie.split(/\.| /, 4)
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
        return [nil, nil, nil] unless digest == OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new(@digest), secret, session_data + timestamp.to_s)
        if @options[:expire_after]
          return [nil, nil, nil] unless timestamp
          return [nil, nil, timestamp] unless Time.now.utc.to_i - timestamp < @options[:expire_after]
        end
        [Marshal.load(session_data), session_data, timestamp]
      else
        [nil, nil, nil]
      end
    else
      [nil, nil, nil]
    end
  rescue Zlib::DataError
    [nil, nil, nil]
  rescue OpenSSLCipherError
    [nil, nil, nil]
  end

  def all_unpacked_cookie_data(env)
    env["action_dispatch.request.unsigned_session_cookie"] ||= begin
      stale_session_check! do
        request = Rack::Request.new(env)
        session_data = request.cookies[@key]
        unmarshal(session_data) || {}
      end
    end
  end

  def unpacked_cookie_data(env)
    all_unpacked_cookie_data(env).first
  end

  def session_refreshed_at(timestamp, env)
    expire_after = env[ENV_SESSION_OPTIONS_KEY][:expire_after] || @options[:expire_after]
    Time.at(timestamp).utc - expire_after if timestamp && expire_after
  end

  # To prevent users from using an insecure encryption key like "Password" we make sure that the
  # encryption key they've provided is at least 30 characters in length.
  def ensure_encryption_key_secure(encryption_key)
    if encryption_key.blank?
      raise ArgumentError, "An encryption key is required for encrypting the " +
        "cookie session data. Please set config.action_controller.session = { " +
        "..., :encryption_key => \"some random string of at least " +
        "16 bytes\", ... } in config/environment.rb"
    end

    if encryption_key.size < 16 * 2
      raise ArgumentError, "The EncryptedCookieStore encryption key must be a " +
        "hexadecimal string of at least 16 bytes. " +
        "The value that you've provided, \"#{encryption_key}\", is " +
        "#{encryption_key.size / 2} bytes. You could use the following (randomly " +
        "generated) string as encryption key: " +
        ActiveSupport::SecureRandom.hex(16)
    end
  end

  def verifier_for(secret, digest)
    nil
  end

  def base64(data)
    ActiveSupport::Base64.encode64(data).tr('+/', '-_').gsub(/=|\n/, '')
  end

  def unbase64(data)
    ActiveSupport::Base64.decode64(data.tr('-_', '+/').ljust((data.length + 4 - 1) / 4 * 4, '='))
  end

    # aka compress
  def deflate(string, level)
    z = Zlib::Deflate.new(level)
    dst = z.deflate(string, Zlib::FINISH)
    z.close
    dst
  end

  # aka decompress
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
