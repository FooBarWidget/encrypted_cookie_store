$LOAD_PATH.unshift(File.expand_path(File.dirname(__FILE__) + "/../lib"))

require 'active_support'
require 'encrypted_cookie_store'

describe EncryptedCookieStore do
  SECRET = "b6a30e998806a238c4bad45cc720ed55e56e50d9f00fff58552e78a20fe8262df61" <<
      "42fcfdb0676018bb9767ed560d4a624fb7f3603b4e53c77ec189ae3853bd1"
  ANOTHER_SECRET = "dd458e790c3b995e3606384c58efc53da431db892f585aa3ca2a17eabe6df75b" <<
      "ce6a45c34607d2048d735b0a31a769de4e1512eb83c7012059a66937158a8975"
  OBJECT = { :user_id => 123, :admin => true, :message => "hello world!" }


  SESSION_KEY = Rack::Session::Abstract::ENV_SESSION_KEY

  class MockApplication
    def initialize(&block)
      @block = block
    end

    def call(env)
      @block.call(env) if @block
    end
  end

  def create_store(options={})
    EncryptedCookieStore.new(options[:app], {:key => 'key', :secret => SECRET}.merge(options))
  end

  def write_headers(store, env={})
    ActionDispatch::Cookies.new(store).send(:call, env)
  end

  specify "marshalling and unmarshalling data works" do
    data   = create_store.send(:marshal, OBJECT)
    object = create_store.send(:unmarshal, data)
    expect(object[:user_id]).to eq(123)
    expect(object[:admin]).to be_truthy
    expect(object[:message]).to eq("hello world!")
  end

  it "uses a different initialization vector every time data is marshalled" do
    store  = create_store
    data1  = store.send(:marshal, OBJECT)
    data2  = store.send(:marshal, OBJECT)
    data3  = store.send(:marshal, OBJECT)
    data4  = store.send(:marshal, OBJECT)
    expect(data1).not_to eq(data2)
    expect(data1).not_to eq(data3)
    expect(data1).not_to eq(data4)
  end

  it "invalidates the data if the encryption key is changed" do
    data   = create_store.send(:marshal, OBJECT)
    object = create_store(:secret => ANOTHER_SECRET).send(:unmarshal, data)
    expect(object).to be_nil
  end

  it "invalidates the data if it was tampered with" do
    store = create_store
    data = store.send(:marshal, OBJECT)
    parts = data.split('.')
    parts[1][0..1] = "AA"
    data = parts.join('.')
    expect(store.send(:unmarshal, data)).to be_nil
  end

  it "invalidates the data if it looks like garbage" do
    store = create_store
    garbage = "\202d\3477 jTf\274\360\200z\355\334N3\001\0036\321qLu\027\320\325*%:%\270D".force_encoding("ASCII-8BIT")
    expect(store.send(:unmarshal, garbage)).to be_nil
  end

  it "should accept a current timestamp" do
    store = create_store
    data = store.send(:marshal, OBJECT, :expire_after => 1.day)
    result = store.send(:unmarshal, data, :expire_after => 1.day)
    timestamp = result.delete(:timestamp)
    expect(timestamp).not_to be_nil
    expect(result).to eq(OBJECT)
  end

  it "should invalidate an old timestamp" do
    yesterday = 5.days.ago
    today = Time.now
    expect(Time).to receive(:now).and_return(yesterday)
    store = create_store
    data = store.send(:marshal, OBJECT, :expire_after => 1.day)
    expect(Time).to receive(:now).and_return(today)
    expect(store.send(:unmarshal, data, :expire_after => 1.day)).to eq(nil)
  end

  it "should compress" do
    # this object doesn't compress well, so we won't try and compress it,
    # regardless of our settings
    obj = {:k => :v}
    store1 = create_store
    store2 = create_store(:compress => false)
    store3 = create_store(:compress => true)
    data1 = store1.send(:marshal, obj)
    data2 = store2.send(:marshal, obj)
    data3 = store3.send(:marshal, obj)
    expect(data1.index(' ')).to be_nil
    expect(data2.index(' ')).to be_nil
    expect(data3.index(' ')).to be_nil
    expect(data1.length).to eq(data2.length)
    expect(data3.length).to eq(data2.length)
    expect(store1.send(:unmarshal, data1)).to eq(obj)
    expect(store2.send(:unmarshal, data2)).to eq(obj)
    expect(store3.send(:unmarshal, data3)).to eq(obj)

    # this object is VERY compressible
    obj = { :some_key => 'value' * 50 }
    data1 = store1.send(:marshal, obj)
    data2 = store2.send(:marshal, obj)
    data3 = store3.send(:marshal, obj)
    expect(data1.index(' ')).not_to be_nil
    expect(data2.index(' ')).to be_nil
    expect(data3.index(' ')).not_to be_nil
    expect(data1.length).to be < data2.length
    expect(data3.length).to be < data2.length
    expect(store1.send(:unmarshal, data1)).to eq(obj)
    expect(store2.send(:unmarshal, data2)).to eq(obj)
    expect(store3.send(:unmarshal, data3)).to eq(obj)
  end

  it "should not refresh the cookie if the session didn't change" do
    parent = MockApplication.new do |env|
      env[SESSION_KEY][:hello] = 'world'
      [200, {}, []]
    end
    store = create_store(:app => parent)

    result = write_headers(store)
    expect(result[1]['Set-Cookie']).not_to be_nil

    env = { 'HTTP_COOKIE' => result[1]['Set-Cookie'] }
    result = write_headers(store, env)
    expect(result[1]).to eq({})
  end

  it "should refresh the cookie if a deep object changed" do
    parent = MockApplication.new do |env|
      session = env[SESSION_KEY]
      if session.has_key?(:hello)
        session[:hello][:other_key] = 2
      else
        session[:hello] = { :one_key => 1 }
      end
      [200, {}, []]
    end
    store = create_store(:app => parent)

    result = write_headers(store)
    expect(result[1]['Set-Cookie']).not_to be_nil

    env = { 'HTTP_COOKIE' => result[1]['Set-Cookie'] }
    result = write_headers(store, env)
    expect(result[1]['Set-Cookie']).not_to be_nil
  end

  it "should refresh the cookie when the timestamp is old enough" do
    now = Time.now
    allow(Time).to receive(:now).and_return(now)
    parent = MockApplication.new do |env|
      env[SESSION_KEY][:hello] = 'world'
      [200, {}, []]
    end
    store = create_store(:app => parent, :expire_after => 1.day, :refresh_interval => 5.minutes)

    result = write_headers(store)
    expect(result[1]['Set-Cookie']).not_to be_nil

    # request right away doesn't refresh
    env = { 'HTTP_COOKIE' => result[1]['Set-Cookie'] }
    result = write_headers(store, env)
    expect(result[1]).to eq({})

    # but in 10 minutes, it does
    allow(Time).to receive(:now).and_return(now + 10.minutes)
    result = write_headers(store, env)
    expect(result[1]['Set-Cookie']).not_to be_nil
  end
end
