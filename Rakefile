desc "Run unit tests"
task :test do
	sh "spec -f s -c test/*_test.rb"
end

desc "Run benchmark"
task :benchmark do
	$LOAD_PATH.unshift(File.expand_path("lib"))
	require 'rubygems'
	require 'benchmark'
	require 'action_controller'
	require 'encrypted_cookie_store'
	
	secret = "b6a30e998806a238c4bad45cc720ed55e56e50d9f00fff58552e78a20fe8262df61" <<
		"42fcfdb0676018bb9767ed560d4a624fb7f3603b4e53c77ec189ae3853bd1"
	encryption_key = "dd458e790c3b995e3606384c58efc53da431db892f585aa3ca2a17eabe6df75b"
	store  = EncryptedCookieStore.new(nil, :secret => secret, :key => 'my_app',
		:encryption_key => encryption_key)
	object = { :hello => "world", :user_id => 1234, :is_admin => true,
	        :shopping_cart => ["Tea x 1", "Carrots x 13", "Pocky x 20", "Pen x 4"],
	        :session_id => "b6a30e998806a238c4bad45cc720ed55e56e50d9f00ff" }
	count  = 50_000
	
	puts "Marshalling and unmarshalling #{count} times..."
	result = Benchmark.measure do
		count.times do
			data = store.send(:marshal, object)
			store.send(:unmarshal, data)
		end
	end
	puts result
	printf "%.3f ms per marshal+unmarshal action\n", result.real * 1000 / count
end