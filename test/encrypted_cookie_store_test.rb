$LOAD_PATH.unshift(File.expand_path(File.dirname(__FILE__) + "/../lib"))
require 'rubygems'
gem 'rails', '~> 2.3.0'
require 'action_controller'
require 'encrypted_cookie_store'

describe EncryptedCookieStore do
  SECRET = "b6a30e998806a238c4bad45cc720ed55e56e50d9f00fff58552e78a20fe8262df61" <<
    "42fcfdb0676018bb9767ed560d4a624fb7f3603b4e53c77ec189ae3853bd1"
  ANOTHER_SECRET = "dd458e790c3b995e3606384c58efc53da431db892f585aa3ca2a17eabe6df75b" <<
    "ce6a45c34607d2048d735b0a31a769de4e1512eb83c7012059a66937158a8975"
  OBJECT = { :user_id => 123, :admin => true, :message => "hello world!" }
  
  def create(options = {})
    EncryptedCookieStore.new(options[:app], options.reverse_merge(
      :key => 'key',
      :secret => SECRET
    ))
  end

  specify "marshalling and unmarshalling data works" do
    data   = create.send(:marshal, OBJECT)
    object = create.send(:unmarshal, data).first
    object[:user_id].should == 123
    object[:admin].should be_true
    object[:message].should == "hello world!"
  end
  
  it "uses a different initialization vector every time data is marshalled" do
    store  = create
    data1  = store.send(:marshal, OBJECT)
    data2  = store.send(:marshal, OBJECT)
    data3  = store.send(:marshal, OBJECT)
    data4  = store.send(:marshal, OBJECT)
    data1.should_not == data2
    data1.should_not == data3
    data1.should_not == data4
  end
  
  it "invalidates the data if the encryption key is changed" do
    data   = create.send(:marshal, OBJECT)
    object = create(:secret => ANOTHER_SECRET).send(:unmarshal, data).first
    object.should be_nil
  end

  it "invalidates the data if we just migrated from CookieStore" do
    old_store = ActionController::Session::CookieStore.new(nil, :key => 'key', :secret => SECRET)
    legacy_data = old_store.send(:marshal, OBJECT)
    store = create
    store.send(:unmarshal, legacy_data).first.should be_nil
  end
  
  it "invalidates the data if it was tampered with" do
    store = create
    data = store.send(:marshal, OBJECT)
    parts = data.split('.')
    parts[1][0..1] = "AA"
    data = parts.join('.')
    store.send(:unmarshal, data).first.should be_nil
  end
  
  it "invalidates the data if it looks like garbage" do
    store = create
    garbage = "\202d\3477 jTf\274\360\200z\355\334N3\001\0036\321qLu\027\320\325*%:%\270D"
    store.send(:unmarshal, garbage).first.should be_nil
  end

  it "should accept a current timestamp" do
    store = create(:expire_after => 1.day)
    data = store.send(:marshal, OBJECT)
    store.send(:unmarshal, data).first.should == OBJECT
  end

  it "should invalidate an old timestamp" do
    yesterday = 5.days.ago
    today = Time.now
    Time.should_receive(:now).and_return(yesterday)
    store = create(:expire_after => 1.day)
    data = store.send(:marshal, OBJECT)
    Time.should_receive(:now).and_return(today)
    store.send(:unmarshal, data).should == [nil, nil, yesterday.to_i]
  end

  it "should compress" do
    # this object doesn't compress well, so we won't try and compress it,
    # regardless of our settings
    obj = {:k => :v}
    store1 = create
    store2 = create(:compress => false)
    store3 = create(:compress => true)
    data1 = store1.send(:marshal, obj)
    data2 = store2.send(:marshal, obj)
    data3 = store3.send(:marshal, obj)
    data1.index(' ').should be_nil
    data2.index(' ').should be_nil
    data3.index(' ').should be_nil
    data1.length.should == data2.length
    data3.length.should == data2.length
    store1.send(:unmarshal, data1).first.should == obj
    store2.send(:unmarshal, data2).first.should == obj
    store3.send(:unmarshal, data3).first.should == obj

    # this object is VERY compressible
    obj = { :some_key => 'value' * 50 }
    data1 = store1.send(:marshal, obj)
    data2 = store2.send(:marshal, obj)
    data3 = store3.send(:marshal, obj)
    data1.index(' ').should_not be_nil
    data2.index(' ').should be_nil
    data3.index(' ').should_not be_nil
    data1.length.should < data2.length
    data3.length.should < data2.length
    store1.send(:unmarshal, data1).first.should == obj
    store2.send(:unmarshal, data2).first.should == obj
    store3.send(:unmarshal, data3).first.should == obj
  end

  it "should not refresh the cookie if the session didn't change" do
    parent = Object.new
    def parent.call(env)
      env['rack.session'][:hello] = 'world'
      [200, {}, []]
    end
    store = create(:app => parent)
    result = store.call({})
    result[1]['Set-Cookie'].should_not be_nil
    env = { 'HTTP_COOKIE' => result[1]['Set-Cookie'] }
    result = store.call(env)
    result[1].should == {}
  end

  it "should refresh the cookie if a deep object changed" do
    parent = Object.new
    def parent.call(env)
      session = env['rack.session']
      if session.has_key?(:hello)
        session[:hello][:other_key] = 2
      else
        session[:hello] = { :one_key => 1 }
      end
      [200, {}, []]
    end
    store = create(:app => parent)
    result = store.call({})
    result[1]['Set-Cookie'].should_not be_nil
    env = { 'HTTP_COOKIE' => result[1]['Set-Cookie'] }
    result = store.call(env)
    result[1]['Set-Cookie'].should_not be_nil
  end

  it "should refresh the cookie when the timestamp is old enough" do
    now = Time.now
    Time.stub!(:now).and_return(now)
    parent = Object.new
    def parent.call(env)
      env['rack.session'][:hello] = 'world'
      [200, {}, []]
    end
    store = create(:app => parent, :expire_after => 1.day, :refresh_interval => 5.minutes)
    result = store.call({})
    result[1]['Set-Cookie'].should_not be_nil

    # request right away doesn't refresh
    env = { 'HTTP_COOKIE' => result[1]['Set-Cookie'] }
    result = store.call(env)
    result[1].should == {}

    # but in 10 minutes, it does
    Time.stub!(:now).and_return(now + 10.minutes)
    result = store.call(env)
    result[1]['Set-Cookie'].should_not be_nil
  end
end
