EncryptedCookieStore
====================
EncryptedCookieStore is similar to Ruby on Rails's CookieStore (it saves
session data in a cookie), but it uses encryption so that people can't read
what's in the session data. This makes it possible to store sensitive data
in the session.

EncryptedCookieStore is written for Rails 2.3. Other versions of Rails have
not been tested.

**Note**: This is _not_ ThinkRelevance's EncryptedCookieStore. In the Rails
2.0 days they wrote an EncryptedCookieStore, but it seems their repository
had gone defunct and their source code lost. This EncryptedCookieStore is
written from scratch by Phusion.

Installation and usage
----------------------

First, add EncryptedCookieStore to your Gemfile

    gem 'encrypted_cookie_store'

Then edit `config/initializers/session_store.rb` and set your session store to
EncryptedCookieStore:

    ActionController::Base.session_store = EncryptedCookieStore

You need to set a few session options before EncryptedCookieStore is usable.
You must set all options that CookieStore needs in `session_store.rb`:

    ActionController::Base.session = {
        # CookieStore options...
        :key            => '_session',     # Name of the cookie which contains the session data.
        :secret         => 'b4589cc9...',  # A secret string used to generate the checksum for
                                           # the session data. Must be longer than 64 characters
                                           # and be completely random.
    }

Operational details
-------------------
Upon generating cookie data, EncryptedCookieStore generates a new, random
initialization vector for encrypting the session data. The session data is
first protected with an HMAC to prevent tampering. The session data is
then compressed with Zlib, and encrypted using 128-bit AES in CBC mode with
the generated initialization vector. This encrypted session data + HMAC are
then stored, along with the initialization vector and a timestamp, into the
cookie.

Upon unmarshalling the cookie data, EncryptedCookieStore
decrypts and decompresses the encrypted session data. The decrypted session
data is then verified against the HMAC. It is also verified that the
timestamp isn't too old, too prevent replay attacks.

EncryptedCookieStore also changes how CookieStore sets the cookie. If the
session has not changed, and the timestamp is less than 5 minutes old, it
will *not* send the cookie to the browser.

EncryptedCookieStore is quite fast: it is able to marshal and unmarshal a
simple session object 5000 times in 8.7 seconds on a MacBook Pro with a 2.4
Ghz Intel Core 2 Duo (in battery mode). This is about 0.174 ms per
marshal+unmarshal action. See `rake benchmark` in the EncryptedCookieStore
sources for details.

EncryptedCookieStore vs other session stores
--------------------------------------------
EncryptedCookieStore inherits all the benefits of CookieStore:

 * It works out of the box without the need to setup a seperate data store (e.g. database table, daemon, etc).
 * It does not require any maintenance. Old, stale sessions do not need to be manually cleaned up, as is the
   case with PStore and ActiveRecordStore.
 * Compared to MemCacheStore, EncryptedCookieStore can "hold" an infinite number of sessions at any time.
 * It can be scaled across multiple servers without any additional setup.
 * It is fast.
 * It is more secure than CookieStore because it allows you to store sensitive data in the session.

There are of course drawbacks as well:

 * It is prone to session replay attacks. These kind of attacks are explained in the
   [Ruby on Rails Security Guide](http://guides.rubyonrails.org/security.html#session-storage). Therefore you
   should never store anything along the lines of `is_admin` in the session. EncryptedCookieStore does
   improve on CookieStore in reducing the amount of time allowed for a replay attack to the :expire_after value,
   instead of forever, but is still weaker than a server side session with an accompanying cookie that allows
   re-establishment of a session, but not replay of the session contents.
 * You can store at most a little less than 4 KB of data in the session because that's the size limit of a
   cookie. "A little less" because EncryptedCookieStore also stores a small amount of bookkeeping data in the cookie.
 * Although encryption makes it more secure than CookieStore, there's still a chance that a bug in
   EncryptedCookieStore renders it insecure. We welcome everyone to audit this code. There's also a chance that
   weaknesses in AES are found in the near future which render it insecure. If you are storing *really* sensitive
   information in the session, e.g. social security numbers, or plans for world domination, then you should
   consider using ActiveRecordStore or some other server-side store.
