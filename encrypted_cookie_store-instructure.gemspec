Gem::Specification.new do |s|
  s.name = %q{encrypted_cookie_store-instructure}
  s.version = "1.2.7"

  s.authors = ["Cody Cutrer", "Jacob Fugal", "James Williams"]
  s.date = %q{2013-12-20}
  s.extra_rdoc_files = [
    "LICENSE.txt"
  ]
  s.files = [
    "LICENSE.txt",
    "README.markdown",
    "lib/encrypted_cookie_store.rb",
    "encrypted_cookie_store-instructure.gemspec"
  ]
  s.homepage = %q{http://github.com/ccutrer/encrypted_cookie_store}
  s.require_paths = ["lib"]
  s.summary = %q{EncryptedCookieStore for Ruby on Rails 4.2}
  s.description = %q{A secure version of Rails' built in CookieStore}

  s.add_dependency "actionpack", ">= 4.2", "< 5.3"

  s.add_development_dependency "rake"
  s.add_development_dependency "rspec-rails", "~> 3.5"
  s.add_development_dependency "byebug"
end
