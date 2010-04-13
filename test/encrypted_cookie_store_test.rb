$LOAD_PATH.unshift(File.expand_path(File.dirname(__FILE__) + "/../lib"))
require 'rubygems'
gem 'rails', '~> 2.3.0'
require 'action_controller'
require 'encrypted_cookie_store'

describe EncryptedCookieStore do
	SECRET = "b6a30e998806a238c4bad45cc720ed55e56e50d9f00fff58552e78a20fe8262df61" <<
		"42fcfdb0676018bb9767ed560d4a624fb7f3603b4e53c77ec189ae3853bd1"
	GOOD_ENCRYPTION_KEY = "dd458e790c3b995e3606384c58efc53da431db892f585aa3ca2a17eabe6df75b"
	ANOTHER_GOOD_ENCRYPTION_KEY = "ce6a45c34607d2048d735b0a31a769de4e1512eb83c7012059a66937158a8975"
	OBJECT = { :user_id => 123, :admin => true, :message => "hello world!" }
	
	def create(options = {})
		EncryptedCookieStore.new(nil, options.reverse_merge(
			:key => 'key',
			:secret => SECRET
		))
	end
	
	it "checks whether an encryption key is given" do
		lambda { create }.should raise_error(ArgumentError, /encryption key is required/)
	end
	
	it "checks whether the encryption key has the correct size" do
		encryption_key = "too small"
		block = lambda { create(:encryption_key => encryption_key) }
		block.should raise_error(ArgumentError, /must be a hexadecimal string of exactly \d+ bytes/)
	end
	
	specify "marshalling and unmarshalling data works" do
		data   = create(:encryption_key => GOOD_ENCRYPTION_KEY).send(:marshal, OBJECT)
		object = create(:encryption_key => GOOD_ENCRYPTION_KEY).send(:unmarshal, data)
		object[:user_id].should == 123
		object[:admin].should be_true
		object[:message].should == "hello world!"
	end
	
	it "uses a different initialization vector every time data is marshalled" do
		store  = create(:encryption_key => GOOD_ENCRYPTION_KEY)
		data1  = store.send(:marshal, OBJECT)
		data2  = store.send(:marshal, OBJECT)
		data3  = store.send(:marshal, OBJECT)
		data4  = store.send(:marshal, OBJECT)
		data1.should_not == data2
		data1.should_not == data3
		data1.should_not == data4
	end
	
	it "invalidates the data if the encryption key is changed" do
		data   = create(:encryption_key => GOOD_ENCRYPTION_KEY).send(:marshal, OBJECT)
		object = create(:encryption_key => ANOTHER_GOOD_ENCRYPTION_KEY).send(:unmarshal, data)
		object.should be_nil
	end
	
	it "invalidates the data if the IV cannot be decrypted" do
		store = create(:encryption_key => GOOD_ENCRYPTION_KEY)
		data  = store.send(:marshal, OBJECT)
		iv_cipher = store.instance_variable_get(:@iv_cipher)
		iv_cipher.should_receive(:update).and_raise(EncryptedCookieStore::OpenSSLCipherError)
		store.send(:unmarshal, data).should be_nil
	end
	
	it "invalidates the data if we just migrated from CookieStore" do
		old_store = ActionController::Session::CookieStore.new(nil, :key => 'key', :secret => SECRET)
		legacy_data = old_store.send(:marshal, OBJECT)
		store = create(:encryption_key => GOOD_ENCRYPTION_KEY)
		store.send(:unmarshal, legacy_data).should be_nil
	end
	
	it "invalidates the data if it was tampered with" do
		store = create(:encryption_key => GOOD_ENCRYPTION_KEY)
		data = store.send(:marshal, OBJECT)
		b64_encrypted_iv, b64_encrypted_session_data = data.split("--", 2)
		b64_encrypted_session_data[0..1] = "AA"
		data = "#{b64_encrypted_iv}--#{b64_encrypted_session_data}"
		store.send(:unmarshal, data).should be_nil
	end
	
	it "invalidates the data if it looks like garbage" do
		store = create(:encryption_key => GOOD_ENCRYPTION_KEY)
		garbage = "\202d\3477 jTf\274\360\200z\355\334N3\001\0036\321qLu\027\320\325*%:%\270D"
		store.send(:unmarshal, garbage).should be_nil
	end
end