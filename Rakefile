#!/usr/bin/env rake
require "bundler/gem_tasks"

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new do |t|
  t.pattern = "test/**/*_test.rb"
  t.rspec_opts = ["-d"]
end
task :default => :spec

desc "Run benchmark"
task :benchmark do
  $LOAD_PATH.unshift(File.expand_path("lib"))
  require 'benchmark'
  require 'encrypted_cookie_store'

  secret = "b6a30e998806a238c4bad45cc720ed55e56e50d9f00fff58552e78a20fe8262df61" <<
    "42fcfdb0676018bb9767ed560d4a624fb7f3603b4e53c77ec189ae3853bd1"
  store  = EncryptedCookieStore.new(nil, :secret => secret, :key => 'my_app',
      :compress => false)
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