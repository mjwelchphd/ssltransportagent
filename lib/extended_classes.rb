class QueryError < StandardError; end

class NilClass

  # these defs allow for the case where something wasn't found to
  # give a nil response rather than crashing--for example:
  #  mx = "example.com" # => nil (because example.com has no MX record)
  #  ip = mx.dig_a # => nil, without crashing
  # otherwise, it would be necessary to write:
  #  mx = "example.com" # => nil (because example.com has no MX record)
  #  ip = if mx then ip = mx.dig_a else ip = nil end
  def dig_a; nil; end
  def dig_aaaa; nil; end
  def dig_mx; nil; end
  def dig_dk; nil; end
  def dig_ptr; nil; end
  def mta_live?(port); nil; end
  def validate_plain; nil; end

end

class String

  # returns list of IPV4 addresses, or nil
  # (there should only be one IPV4 address)
  def dig_a
    Resolv::DNS.open do |dns|
      txts = dns.getresources(self,Resolv::DNS::Resource::IN::A).collect { |r| r.address.to_s }
      if txts.empty? then nil else txts[0] end
    end
  end

  # returns list of IPV6 addresses, or nil
  # (there should only be one IPV6 address)
  def dig_aaaa
    Resolv::DNS.open do |dns|
      txts = dns.getresources(self,Resolv::DNS::Resource::IN::AAAA).collect { |r| r.address.to_s.downcase }
      if txts.empty? then nil else txts[0] end
    end
  end

  # returns list of MX names, or nil
  # (there may be multiple MX names for a domain)
  def dig_mx
    Resolv::DNS.open do |dns|
      txts = dns.getresources(self,Resolv::DNS::Resource::IN::MX).collect { |r| r.exchange.to_s }
      if txts.empty? then nil else txts end
    end
  end

  # returns a publibdomainkey, or nil
  # (there should only be one DKIM public key)
  def dig_dk
    Resolv::DNS.open do |dns|
      txts = dns.getresources(self,Resolv::DNS::Resource::IN::TXT).collect { |r| r.strings }
      if txts.empty? then nil else txts[0][0] end
    end
  end

  # returns a reverse DNS hostname or nil
  def dig_ptr
    begin
      Resolv.new.getname(self.downcase)
    rescue Resolv::ResolvError
      nil
    end
  end

  # opens a socket to the IP/port to see if there is an SMTP server
  # there - returns "250 ..." if the server is there, or 
  # times out in 5 seconds to prevent hanging the process
  def mta_live?(port)
    tcp_socket = nil
    welcome = nil
    begin
      Timeout.timeout(5) do
        begin
          tcp_socket = TCPSocket.open(self,port)
        rescue Errno::ECONNREFUSED => e
          return "421 Service not available (port closed)"
        end
        begin
          welcome = tcp_socket.gets
          return welcome if welcome[1]!='2'
          tcp_socket.write("QUIT\r\n")
          line = tcp_socket.gets
          return line if line[1]!='2'
        ensure
          tcp_socket.close if tcp_socket
        end
      end
      return "250 #{welcome.chomp[4..-1]}"
    rescue SocketError => e
      return "421 Service not available (#{e.to_s})"
    rescue Timeout::Error => e
      return "421 Service not available (#{e.to_s})"
    end
  end

  # this validates a password with the base64 plaintext in an AUTH command
  # encoded -> AGNvY29AY3phcm1haWwuY29tAG15LXBhc3N3b3Jk => ["coco@example.com", "my-password"]
  # "my-password" --> {CRYPT}IwYH/ZXeR8vUM
  # "AGNvY29AY3phcm1haWwuY29tAG15LXBhc3N3b3Jk".validate_plain { "{CRYPT}IwYH/ZXeR8vUM" } => true
  # "AGNvY29AY3phcm1haWwuY29tAHh4LXBhc3N3b3Jk".validate_plain { "{CRYPT}IwYH/ZXeR8vUM" } => false
  def validate_plain
    # decode and split up the username and password)
    username, password = Base64::decode64(self).split("\x00")[1..-1]
    passwd_hash = yield(username) # get the hash
    m = passwd_hash.match(/^{(.*)}(.*)$/)
    UnixCrypt.valid?(password, m[2])
  end

=begin
ipv4 = "example.com".dig_a
ipv6 = "example.com".dig_aaaa
"example.com".dig_mx
"key._domainkey.example.com".dig_dk
"bcgdjftu.com".dig_a
"bcgdjftu.com".dig_aaaa
"bcgdjftu.com".dig_mx
"crap._domainkey.example.com".dig_dk
ipv4.dig_ptr
ipv6.dig_ptr

cm="example.com" # the domain from someone@example.com
mx=cm.dig_mx # the mail server host for example.com
ma=mx[0].dig_a # the IP of the mail server host
ma.mta_live?(25) # "2..." if exists, and "4..." if not
=end

  # this is used to convert numbers in the email IDs back to
  # base 10
  def from_b(base=10)
    n = 0
    self.each_char do |ch|
      n = n*base
      m = ch.ord
      case
      when m>=97
        k = m-61
      when m>=65
        k = m-55
      when m>=48
        k = m-48
      end
      n += k
    end
    return n
  end

end

class Numeric

  # this is used to convert a number into segments of
  # base 62 (or 36) for use in creating email IDs
  def to_b(base=10)
    n = self
    r = ""
    while n > 0
      m = n%base
      n /= base
      case
      when m>=36
        k = m+61
      when m>=10
        k = m+55
      when m>=0
        k = m+48
      end
      r << k.chr
    end
    return r.reverse
  end

end
