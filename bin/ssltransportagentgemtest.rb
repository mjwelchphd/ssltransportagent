#! /usr/bin/ruby

#require 'pretty_inspect'
#require 'pdkim'

#class TAServer
#  def restart
#    # handle a HUP request here
#  end
#end

module ServerConfig
  ServerName = "mail.example.com"
  PrivateKey = "rubymta.key" # filename or nil
  Certificate = "rubymta.crt" # filename or nil
  Host = {
    :host => nil, # "localhost" (usually), or nil if MySQL not used
    :username => nil,
    :password => nil,
    :database => nil
  }
  # ListeningPort is a list of ip+port numbers
  # an IPV4 ip+port might be "93.184.216.34:2000", or "127.0.0.1:2000", or "0.0.0.0:2000"
  # an IPV6 ip+port might be "2606:2800:220:1:248:1893:25c8:1946/2000", "::1/2000", or "0:0:0:0:0:0:0:0/2000"
  # an IPV4 port number might be ["2000"] -- this is equivalent to "0.0.0.0:2000"
  ListeningPort = ['2000'] # ['0.0.0.0:2000'] # or ['0:0:0:0:0:0:0:0/2000'] for IPV6
  UserName = "username" # must be present if ssltransportagent run as root
  GroupName = "usergroup" # must be present if ssltransportagent run as root
  WorkingDirectory = "myta/" # directory or nil
  LogPathAndFile = "ssltransportagentgemtest.log"
  LogFileLife = "daily"
end

module ReceiverConfig
  ReceiverTimeout = 30 # seconds
  RemoteSMTPPort = 25 # port 25 is the submitter port for remotes
  LogConversation = false # enables the logging of the conversation
end

require 'ssltransportagent'

#-------------------------------------#
#---    ACCESS TO DB OPEN/CLOSE    ---#
#-------------------------------------#

# To get access to the open and close of the database, use this:
#
#class TAServer
#  def db_open
#    # do something after the db is opened
#  end
#
#  def db_close
#    # do something before the db is closed
#  end
#end

# test with:
# swaks -tls -a plain -s mail.your-test-server.com:2000 -t coco@example.com -f mjwelchphd@gmail.com
# Username: coco@example.com
# Password: my-password
#
# check the log after sending to see the received data
#
# NOTE:
# This TEST is NOT PRODUCTION software -- just a test. If anything goes wrong (like you send the
# wrong data to it), it may do strange things. It has no error checking or recovery. It's NOT
# PRODUCTION software. If you do the test right, and this executes correctly, the gem is
# working properly.
class TAReceiver

  Patterns = [
    [0, "[ /t]*QUIT[ /t]*", :quit],
    [1, "[ /t]*AUTH[ /t]*(.+)", :auth],
    [1, "[ /t]*EHLO(.*)", :ehlo],
    [1, "[ /t]*EXPN[ /t]*", :expn],
    [1, "[ /t]*HELO[ /t]+(.*)", :ehlo],
    [1, "[ /t]*HELP[ /t]*", :help],
    [1, "[ /t]*NOOP[ /t]*", :noop],
    [1, "[ /t]*RSET[ /t]*", :rset],
    [1, "[ /t]*TIMEOUT[ /t]*", :timeout],
    [1, "[ /t]*VFRY[ /t]*", :vfry],
    [2, "[ /t]*STARTTLS[ /t]*", :starttls],
    [2, "[ /t]*MAIL FROM[ /t]*:[ \t]*(.+)", :mail_from],
    [3, "[ /t]*RCPT TO[ /t]*:[ \t]*(.+)", :rcpt_to],
    [4, "[ /t]*DATA[ /t]*", :data]
  ]
  MessageIdBase = 62 # 62 for Linux, 36 for OSX and Cygwin

#-------------------------------------#
#---   LOOP TO RECEIVE COMMANDS    ---#
#-------------------------------------#

  def receive(local_port, local_hostname, remote_port, remote_hostname, remote_ip)
    # Start a hash to collect the information gathered from the receive process
    @mail = {}
    message_id = []
    message_id[0] = Time.now.tv_sec.to_b(MessageIdBase)
    message_id[1] = ("00000"+(2176782336*rand).to_i.to_b(MessageIdBase))[-6..-1]
    message_id[2] = ("00"+(Time.now.usec/1000).to_i.to_b(MessageIdBase))[-2..-1]
    @mail[:id] = message_id.join("-")
    @mail[:local_port] = local_port
    @mail[:local_hostname] = local_hostname
    @mail[:remote_port] = remote_port
    @mail[:remote_hostname] = remote_hostname
    @mail[:remote_ip] = remote_ip

    # start the main receiving process here
    @done = false
    @encrypted = false
    @authenticated = false
    @mail[:encrypted] = false
    @mail[:authenticated] = nil
    connect(remote_ip)
    @level = 1
    begin
      text = recv_text(true)
      unrecognized = true
      Patterns.each do |pattern|
        break if pattern[0]>@level
        m = text.match(/^#{pattern[1]}$/i)
        if m
          response = send(pattern[2], m[1])
          @done = true if pattern[2] == :quit
          unrecognized = false
          break
        end
      end
      if unrecognized
        response = "500 5.5.1 Unrecognized command, incorrectly formatted command, or command out of sequence"
        send_text(response)
      end
    rescue OpenSSL::SSL::SSLError => e
      @log.error {"SSL error: #{e.to_s}"}
    end until @done
#    @log.info { "Received Mail:\r\n#{@mail.pretty_inspect}" }
    @log.info { "Received Mail:\r\n#{@mail.inspect}" }
  end

#-------------------------------------#
#--- SMTP COMMAND HANDLING METHODS ---#
#-------------------------------------#

  def connect(remote_ip)
    @level = 1
    send_text("220 2.0.0 #{ServerName} ESMTP #{Time.new.strftime("%^a, %d %^b %Y %H:%M:%S %z")}")
    @log.info {"Connection from #{remote_ip}"}
  end

  def ehlo(value)
    @mail[:ehlo] = mail = {}
    mail[:value] = value
    if value.index(".")
      mail[:domain] = domain = value.split(".").collect{ |item| item.strip }[-2..-1].join(".")
      mail[:ip] = ip = domain.dig_a
    else
      mail[:domain] = nil
      mail[:ip] = nil
    end
    text = "250-2.0.0 #{ServerName} Hello"
    text << " #{domain}" if domain
    text << " at #{ip}" if ip
    send_text(text)
    send_text("250-AUTH PLAIN")
    send_text("250-STARTTLS")
    send_text("250 HELP")
    @level = 2
  end

  def mail_from(value)
    @mail[:mailfrom] = from = {}
    from[:value] = value
    name = url = user = domain = mx = ip = nil
    m = value.match(/^(.*)<(.*)>$/)
    if m
      from[:name] = name = m[1].strip if !m[1].empty?
      from[:url] = url = m[2].strip if !m[2].empty?
    end
    user, domain = url.split("@") if url
    mx = domain.dig_mx if domain
    from[:mx] = mx
    from[:ip] = if mx then from[:mx][0].dig_a else nil end
    @level = 3
    send_text("250 2.0.0 OK")
  end

  def rcpt_to(value)
    @mail[:rcptto] ||= []
    rcpt = {}
    rcpt[:value] = value
    value = if value.empty? then nil else value end
    name = url = user = domain = mx = ip = nil
    if value
      user = domain = nil
      m = value.match(/^(.*)<(.*)>$/)
      if m
        rcpt[:name] = name = m[1].strip if !m[1].empty?
        rcpt[:url] = url = m[2].strip if !m[2].empty?
      end
      user, domain = url.split("@") if url
      rcpt[:mx] = mx = domain.dig_mx
      rcpt[:ip] = ip = if mx then rcpt[:mx][0].dig_a else nil end
      rcpt[:live] = smtp = if ip then ip.mta_live?(RemoteSMTPPort)[0]=='2' else false end
    end
    @mail[:rcptto] << rcpt
    @level = 4
    send_text("250 2.0.0 OK")
  end

  def data(value)
    @mail[:data] = mail = {}
    mail[:value] = value
    has_rcpt = false
    @mail[:rcptto].each { |rcpt| has_rcpt = true if rcpt[:live] }
    if !has_rcpt
      send_text("501 5.5.1 Bad sequence of commands (there was no valid recipient)")
    else
      lines = []
      send_text("354 2.0.0 Enter message, ending with \".\" on a line by itself")
      @log.info {" -> (email message)"}
      while true
        text = recv_text(false)
        break if text=="."
        lines << text
      end
      mail[:text] = lines
    end
      # if there are DKIM signatures, verify them
      # requires PDKIM gem
#      ok, signatures = pdkim_verify_an_email(PDKIM_INPUT_NORMAL, @mail[:data])
#      signatures.each do |signature|
#        @log.info(message_id){"Signature for '%s': %s"%[signature[:domain], PdkimReturnCodes[signature[:verify_status]]]}
#        @mail[:signatures] ||= []
#        @mail[:signatures] << [signature[:domain], signature[:verify_status]]
#      end if ok==PDKIM_OK
    send_text("250 OK #{@mail[:id]}")
  end

  def rset(value)
    @level = 0
    send_text("250 2.0.0 Reset OK")
  end

  def vfry(value)
    # SMTP includes commands called "VRFY" and "EXPN" which do exactly what verification services offer. 
    # While those two functions are technically different, they both reveal to a third party whether email 
    # addresses exist in the server's userbase. Nearly every Postmaster (mail server administrator) on the 
    # Internet has turned off VRFY and EXPN due to abuse by spammers trying to harvest addresses, as well 
    # as a general security and privacy measure required by most network's operational policies. In fact, 
    # since about 1999 or before, all mail servers are installed with those off by default. That should 
    # give a clear indication to email verifiers about the opinion of Postmasters of the service they 
    # intend to offer. Doing verification against systems that have disabled those functions, whether 
    # successful or not, constitutes an attempted breach of the receiver's security policies and may be 
    # considered a hostile act by site administrators. Sending high volumes of verification probes without 
    # an attempt to actually send an email will often trigger filters or firewalls, thus invalidating the 
    # data and impairing future verification accuracy.
    # -- http://www.spamhaus.org/news/article/722/on-the-dubious-merits-of-email-verification-services
    #
    # What this means for you is: if a spammer sends spam and you try to validate the sender's email
    # address, and it's a SPAMHAUS or other blacklist company's trap address, *YOU* will be blacklisted.
    # Don't use VFRY or EXPN, and don't use a EHLO, MAIL FROM, RCPT TO, QUIT sequence either.
    # The takeaway here: thanks to spammers and Spamhaus, you can't verify a sender's or recipient's
    # address safely.
    ["252 2.5.1 Administrative prohibition"]
  end

  def expn(value)
    # (see the note above)
    ["252 2.5.1 Administrative prohibition"]
  end

  def help(value)
    send_text("250 2.0.0 QUIT AUTH, EHLO, EXPN, HELO, HELP, NOOP, RSET, VFRY, STARTTLS, MAIL FROM, RCPT TO, DATA")
  end

  def noop(value)
    send_text("250 2.0.0 OK")
  end

  def quit(value)
    send_text("221 2.0.0 OK #{ServerName} closing connection")
    @done = true
  end

  # for testing, use:
  #
  # swaks -tls -a plain -s mail.example.com:2000 -t coco@example.com -f mjwelchphd@gmail.com
  # Username: coco@czarmail.com
  # Password: my-password
  #
  # NOTE: replace mail.example.com:2000 with your test server domain or ip
  #
  # swaks will send AUTH PLAIN AGNvY29AY3phcm1haWwuY29tAG15LXBhc3N3b3Jk
  # for its authorization request. The code AGNvY...3b3Jk is base64.
  #
  #   AGNvY29AY3phcm1haWwuY29tAG15LXBhc3N3b3Jk decoded => ["coco@czarmail.com", "my-password"]
  #   "my-password" hashed => {CRYPT}IwYH/ZXeR8vUM
  #
  # The 'validate_plain' method will decode it into username/password and yield(username)
  # to the caller's block, which looks up the {CRYPT} hash for username. In the test
  # code, then {CRYPT} hash is simply returned always for testing. The method checks the
  # given password against the hash, and if it matches, it returns true; else false.
  #
  # "AGNvY29AY3phcm1haWwuY29tAG15LXBhc3N3b3Jk".validate_plain { "{CRYPT}IwYH/ZXeR8vUM" } => "coco@czarmail.com", true
  def auth(value)
    auth_type, auth_encoded = value.split
    # auth_encoded contains both username and password
    case auth_type.upcase
    when "PLAIN"
      # get the password hash from the database
      username, ok = auth_encoded.validate_plain do |username|
        "{CRYPT}IwYH/ZXeR8vUM" # for testing
      end
      if ok
        send_text("235 2.0.0 Authentication succeeded")
        @mail[:authenticated] = username
      else
        send_text("530 5.7.8 Authentication failed")
      end
    else
      send_text("504 5.7.4 authentication mechanism not supported")
    end
  end

  def starttls(value)
    send_text("220 2.0.0 TLS go ahead")
    @log.info {"<-> (handshake)"}
    @connection.accept
    @encrypted = true
    @mail[:encrypted] = true
  end

  def timeout(value)
    send_text("500 5.7.1 #{"<mail id>"} closing connection due to inactivity--%s was NOT saved")
    @done = true
  end
end

begin
  TAServer.new.main
rescue => e
  puts "Catastrophic failure => %s"%e
  puts e.backtrace
end
