# SSL Transport Agent
The SSL Transport Agent Ruby gem is a foundation for building servers that communicate over the web using Secure Sockets.

#### It has the following features:
1. It can listen on any number of ports simultaneously.
2. It starts a separate receiver process to handle each connection.
3. The server may run as root, but the processes will lose their root privileges soon after creation. This is a security feature.
4. The receiver processes can switch on full encryption (STARTTLS in a mail server, for example).
5. A log file is built in.
6. MySQL database is built in. A simple to use MySQL API is built in.
7. Runs until terminated by a KILL or ^C.
8. A set of DNS queries is built in.
9. A SMTP server tester (to see if a given MX has a live mail server running) is built in.
10. A method to validate AUTH PLAIN (Linux CRYPT) hashes.

#### It comes with a fully fleshed out SMTP receiver
The ssltransportagentgemtest.rb application implements a simple receiver for an email server. This test program not only verifies whether or not the gem is functioning correctly, but also serves to demonstrate how to build an application that sits on top of ssltransportagent gem.

Too often the problem with using an otherwise useful gem is the lack of documentation. Even *very* important classes like SSLSocket sometimes have too little documentation to be able to implement their functionality. In fact, most of the posts on the Internet on how to use SSL Sockets **_are wrong!_** If you really want to know how it's done correctly, study the lib/ssltransportagent.rb file in this gem.

Having a working demo application helps to solve this documentation problem, which is why it was included here.

# Version 1.0 is considered a stable release
This server has been tested by sending it over 23,000 spam emails. No faults were found. It's licensed under the MIT license, so technically, you're on your own. But practically, drop me an email at mjwelchphd@gmail.com if you need help with this. I want it to be useful, stable, and reliable.

## v1.04 is in pseudo-production testing
A few problems and errors have surfaced since starting pseudo-production testing, which explains why there have been 4 updates in such a short period of time. I discovered that I needed more code to handle both IPv4 and IPv6 *and* IP-to-port binding (so that the server can be run only on localhost, or only on the outside network, for example).

# Gem Dependancies
This gem requires the following:
```ruby
require 'openssl'
require 'logger'
require 'mysql2'
require 'net/telnet'
require 'resolv'
require 'etc'
require 'base64'
require 'unix_crypt'
```
All of these packages are found in the Ruby Standard Library (stdib 2.2.2 at the time of this writing), except unix-crypt. They are required in the gem itself, so you don't have to require them. Get unix-crypt with *gem*, if you don't already have it:
```bash
$ sudo gem install unix-crypt
```

# TODO
* Add parameter processing to implement the following:
* Add a switch to start as a daemon
* Add a switch to shutdown the daemon
* Add a switch to restart the deamon
* Build an /etc/init.d command file
* Improve the documentation by adding a detailed description of the configuration parameters

# Creating a Self-Signed Certificate
Use OpenSSL to create a self-signed certificate for testing as follows:
```bash
$ openssl req -x509 -newkey rsa:2048 -keyout example.key -out example.crt -days 9000 -nodes
$ chmod 400 example.key
$ chmod 444 example.crt
```

# How to Get SSL Transport Agent Gem

To install the gem, simply use the *gem* application:
```bash
$ sudo gem install ssltransportagentgemtest
```
Alternately, you can clone the project on GitHub at:
```bash
https://github.com/mjwelchphd/ssltransportagent
```
and build it yourself.

# How to Build a Basic Server

The basic server looks like this:
```ruby
#! /usr/bin/ruby

module ServerConfig
  # ServerName, PrivateKey, and Certificate are required
  ServerName = "mail.example.com"
  PrivateKey = "example.key" # filename or nil
  Certificate = "example.crt" # filename or nil
  # if Host is specified, a MySQL connection will be opened
  Host = {
    :host => nil, # "localhost" (usually), or nil if MySQL not used
    :username => nil,
    :password => nil,
    :database => nil
  }
  # ListeningPort is a list of ip+port numbers
  # an IPV4 ip+port might be "93.184.216.34:2000", or "127.0.0.1:2000", or "0.0.0.0:2000"
  # an IPV6 ip+port might be "2606:2800:220:1:248:1893:25c8:1946/2000", "::1/2000", or "0:0:0:0:0:0:0:0/2000"
  # an IPV4 port number might be just a port like ["2000"] -- this is equivalent to []"0.0.0.0:2000"]
  ListeningPort = ['2000']
  # UserName, GroupName, and WorkingDirectory must be present if ssltransportagent run as root
  # otherwise, they may be nil
  UserName = "username"
  GroupName = "groupname"
  WorkingDirectory = "mywd/"
  # if not specified, the log will go to the working directory
  # see http://ruby-doc.org/stdlib-2.2.3/libdoc/logger/rdoc/Logger.html for more info
  LogPathAndFile = "ssltransportagentgemtest.log"
  LogFileLife = "daily"
end

module ReceiverConfig
  ReceiverTimeout = 30 # seconds
  RemoteSMTPPort = 25
end

require 'ssltransportagent'

class TAReceiver
  def receive(local_port, local_hostname, remote_port, remote_hostname, remote_ip)
    (initialization)
    send_text("220 mail.example.com ESMTP")
    done = false
    begin
      text = recv_text
      done = text.start_with?("QUIT")
      (process received data)
      send_text("250 some response")
    end until done
    (process received data further)
  end
end
```
The test application included in the gem is bin/ssltransferagentgemtest.rb. It has a comple email receiver to demonstrate how to build your application.

## Methods Available in Class TAServer

### HUP and TERM (^C) traps

A `kill -TERM <pid>` or `<ctrl-C>` will terminate the server.
```ruby
$ ssltransportagentgemtest.rb
^C
ssltransportagentgemtest terminated by admin ^C
$
```
A `kill -HUP <pid>` will activate a TAServer::restart method, if you have one defined in your code.
```ruby
class TAServer
  def restart
  	puts "I just got a HUP request."
  end
end
```
then at another terminal:
```ruby
$ ps ax | grep ssltra
  823 pts/0    Sl+    0:00 ssltransportagentgemtest.rb
  829 pts/1    S+     0:00 grep --color=auto ssltra
$ kill -hup 823
```
will result in:
```
ssltransportagent received a HUP request
I just got a HUP request.
```
at the terminal where `ssltransportagentgemtest.rb` is running, with no other action. The first message comes from `ssltransportagent` itself, and the second comes from the `def restart`.

## Methods Available in Class TAReceiver

### IO Methods

#### send_text
```ruby
send_text(text,echo)
```
The send_text method sends `text` to the client while adding a `<cr><lf>` at the end of each line. The `echo` parameter can be true (default) or false, and determines whether or not the text will be copied into the log.

The `text` parameter may be a single String, or an Array of Strings.

#### recv_text
```ruby
text = recv_text(echo)
```
The recv_text method receives one line of text from the client, strips off the `<cr><lf>`, and returns the text. It *does not* make any other changes to the text, such as stripping off leading and trailing spaces. The `echo` parameter can be true (default) or false, and determines whether or not the text will be copied into the log.

If a timeout occurs, recv_text makes an entry into the log of `" -> <eod>"`, then returns nil.


### Query Methods
#### query_esc
```ruby
escaped_string = query_esc(string)
```
Special characters in the String `string` are replaced, i.e., hex 0D character will be replaced with `\r`, et.al. This method prevents users from passing parameters that execute as code.

#### query_act
```ruby
query_act(qry)
```
The action query `qry` is executed. No return value is expected. An error will raise QueryError.

#### query_all
```ruby
query_all(qry)
```
The result query `qry` is executed and the results are returned. For example, here is how the query returns data:

```ruby
result = query_all("select id,created_at from domains where kind=1")
=>  [ {
        :id=>6,
        :created_at=>2013-11-18 03:38:36 +0000
      },
      {
        :id=>7,
        :created_at=>2013-12-27 18:34:21 +0000
      }
    ]
```


#### query_one
```ruby
result = query_one(qry)
```
The result query `qry` is executed and one row is returned. For example, here is how the query returns data:
```ruby
result = query_one("select id,created_at from domains where kind=1")
=> {
     :id=>6,
     :created_at=>2013-11-18 03:38:36 +0000
   }
```
This method is designed for a query that is intended to only select one row.


#### query_value
```ruby
result = query_value(qry)
```
This query is designed to return a single value from the database. For example, here is how the query returns data:

```ruby
result = query_value("select created_at from domains where id=12", :created_at)
=> 2014-05-29 21:22:21 +0000
```

### DNS Methods

#### dig_a
```ruby
result = "example.com".dig_a
```
This method looks up an A record in the domain's DNS. It returns the IPv4 address or nil, if the record is not found. For example,
```ruby
ip = "example.com".dig_a
=> "93.184.216.34"
```


#### dig_aaaa
```ruby
result = "example.com".dig_aaaa
```
This method looks up an AAAA record in the domain's DNS. It returns the IPv6 address or nil, if the record is not found. For example,
```ruby
ip = "example.com".dig_aaaa
=> "2606:2800:220:1:248:1893:25c8:1946"
```


#### dig_mx
```ruby
result = "github.com".dig_mx
```
This method looks up an MX record in the domain's DNS. It returns the list of MX records or nil, if there are none. For example,
```ruby
ip = "github.com".dig_mx
=> ["ALT1.ASPMX.L.GOOGLE.COM", "ALT2.ASPMX.L.GOOGLE.COM", "ALT3.ASPMX.L.GOOGLE.COM", "ALT4.ASPMX.L.GOOGLE.COM", "ASPMX.L.GOOGLE.COM"]
```


#### dig_dk
```ruby
result = "key._domainkey.czarmail.com".dig_dk
```
This method looks up a domain key public key in the domain's DNS. It returns the key or nil, if there is none. For example,
```ruby
ip = "key._domainkey.czarmail.com".dig_dk
=> "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC647BjD66umGm6Mip8b2WWx/WCWGU5BM34yCWn1aUfwbVL/Ng+hyTwaOU/bI58nIV1DjpJKxc+hVwe5Bq2zYtlu5/H3K8lr5c/1P/L4ttH+B67PLzzmTZRShNxcTlp5Ge3VZ8GoG2dhfniIikGVGjSL0OSnGvKktbIxOWc+DaaGQIDAQAB"
```
Notice that the request has to be formed as the selector from the DKIM signature being validated ("key" in this case) + "_domainkey" + domain. See the example.


#### dig_mx
```ruby
result = "github.com".dig_mx
```
This method looks up an MX record in the domain's DNS. It returns the list of MX records or nil, if there are none. For example,
```ruby
ip = "github.com".dig_mx
=> ["ALT1.ASPMX.L.GOOGLE.COM", "ALT2.ASPMX.L.GOOGLE.COM", "ALT3.ASPMX.L.GOOGLE.COM", "ALT4.ASPMX.L.GOOGLE.COM", "ASPMX.L.GOOGLE.COM"]
```


#### dig_ptr
```ruby
result = "23.253.107.107".dig_ptr
```
This method looks up a PTR record (sometimes called a reverse DNS address) in the domain's DNS. It returns the address or nil, if there is none. For example,
```ruby
result = "23.253.107.107".dig_ptr
=> "mail.czarmail.com"
```
Take into account that many websites don't have a reverse address DNS record. This is something commonly associated with SMTP servers, and is used to find the domain name of the client which is connecting with the intent to send email. Since it's common for large systems to route outgoing mail through a MSA (Mail Submissin Agent), there is no guarantee that the sender's domain will be the same as the MSA's domain.

#### blacklisted?
```ruby
barracuda = 'b.barracudacentral.org'.blacklisted?(ip)
spamhaus = 'zen.spamhaus.org'.blacklisted?(ip)
```
This method looks the given IP up on the blacklist and returns `true` or `false`. Each blacklist will tell on it's web site what the URL is for querying that blacklist'

#### utf8
```ruby
utf8_string = "string with possible multi-wide (Unicode) characters".utf8
```
The given string is properly encoded into UTF-8 (Unicode) and if there are faulty character sequences in the string, replaces them with a '?'.

**Be careful using this with email:**
Email has to be received and transported with **_NO_** changes, except for the addition of extra headers at the beginning (before any DKIM headers). Some mail servers will remove leading and trailing spaces, convert tabs to spaces, etc. If there is a DKIM header in the email, after those changes, the DKIM *will not* verify. According to the RFC, an email must *not* contain non-ascii characters, unless they are properly encoded, but some emailers ignore the rule.

This can be useful in translating the headers after they are parsed (leaving the original headers intact) in order to avoid unexpected results in Ruby.

### SMTP Server Live Test

#### mta_live?(port)
```ruby
ok = domain.mta_live?(port)
```
This method opens a socket to the IP/port to see if there is an SMTP server there. If a server responds, it returns a 250 or 421, depending on whether or not there was a mail server there. It times out in 5 seconds to prevent hanging the process. For example:
```ruby
ok = "mail.czarmail.com".mta_live?(587)
=> "250 mail.czarmail.com ESMTP Czar Mail Exim 4.84 Tue, 29 Sep 2015 05:45:16 +0000"

ok = "example.com".mta_live?(25)
=> "421 Service not available (execution expired)"
or
=> "421 Service not available (getaddrinfo: Name or service not known)"
```

### Validation Methods

#### validate_plain
This method validates a password using the base64 plaintext in an AUTH command. A typical AUTH command might look like this:
```ruby
AUTH PLAIN AGNvY29AY3phcm1haWwuY29tAG15LXBhc3N3b3Jk
```
The value part of the command is a base 64 encoded message. For example:
```ruby
decoded = Base64::decode64("AGNvY29AY3phcm1haWwuY29tAG15LXBhc3N3b3Jk")
=> "\x00coco@czarmail.com\x00my-password"
or
=> decoded.split("\x00")[1..-1] => ["coco@example.com", "my-password"]
```
The validate_plain method decodes the AUTH PLAIN value, gets the username and password, and yields the password to the block. The block looks up the password hash for someplace (someplace your application stores it), then returns that. The validate_plain method validates the password from the AUTH PLAIN value against the user's password hash to see if it is valid or not. For example:
```ruby
"AGNvY29AY3phcm1haWwuY29tAG15LXBhc3N3b3Jk".validate_plain { |username| "{CRYPT}IwYH/ZXeR8vUM" }
=> "coco@example.com", true
"AGNvY29AY3phcm1haWwuY29tAHh4LXBhc3N3b3Jk".validate_plain { |username| "{CRYPT}IwYH/ZXeR8vUM" }
=> "", false
```
In this example, of course, we ignore |username| and don't look up the hash: we just return the hash we're using for testing. The second one is an example of a wrong password, so it fails. A malformed uathorization string may be undecipherable, and so will return "", false, as will a nil value.
```ruby
"This is not a legitamate base 64 encoded string".validate_plain { |username| "" }
=> "", false
```

# See Also
The [smtptransportagent gem](https://github.com/mjwelchphd/smtptransportagent) is an email transporter which sits on top of this gem.
