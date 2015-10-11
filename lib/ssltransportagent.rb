require 'openssl'
require 'logger'
require 'mysql2'
require 'net/telnet'
require 'resolv'
require 'base64'
require 'unix_crypt'
require_relative 'extended_classes'
require_relative 'query_helpers'

class TATerminate < Exception; end
class TAIncomplete < Exception; end

class TAServer

  include ServerConfig

  # this is the code executed after the process has been
  # forked and root privileges have been dropped
  def process_call(log, local_port, connection)
    begin
      Signal.trap("INT") { } # ignore ^C in the child process
      address_family, remote_port, remote_hostname, remote_ip = connection.peeraddr
      log.info {"Connection accepted on port #{local_port} from port #{remote_port} at #{remote_ip} (#{remote_hostname})"}
      # a new object is created here to provide separation between server and receiver
      # this call receives to email and does basic validation
      TAReceiver::new(log, connection) { |rcvr| rcvr.receive(local_port, Socket::gethostname, remote_port, remote_hostname, remote_ip) }
    rescue => e
      log.fatal {"Rescue of last resort => #{e.to_s}"}
      e.backtrace.each {|line| log.fatal {line}}
      exit(9)
    end
  end

  def drop_root_privileges(user_name, group_name, working_directory)
    # drop root privileges
    if Process::Sys.getuid==0
      user = Etc::getpwnam(user_name)
      group = Etc::getgrnam(group_name)
      Dir.chdir(user.dir)
      Dir.chdir(working_directory) if not working_directory.nil?
      Process::GID.change_privilege(group.gid)
      Process::UID.change_privilege(user.uid)
    end
  end

  def listening_thread(local_port)
    @log.info {"listening on port #{local_port}..."}

    # establish an SSL context
    $ctx = OpenSSL::SSL::SSLContext.new
    $ctx.key = $prv
    $ctx.cert = $crt
    ssl_server = OpenSSL::SSL::SSLServer.new(TCPServer.new(local_port), $ctx);
    ssl_server.start_immediately = false
    loop do
      # we can't use threads because if we drop root privileges on any thread,
      # they will be dropped for all threads in the process--so we have to fork
      # a process here in order that the reception be able to drop root privileges
      # and run at a user level--this is a security precaution
      connection = ssl_server.accept
      Process::fork do
        drop_root_privileges(UserName,GroupName,WorkingDirectory) if !UserName.nil?
        process_call(@log, local_port, connection)
        # here we close the child's copy of the connection --
        # since the parent already closed it's copy, this
        # one will send a FIN to the client, so the client
        # can terminate gracefully
        connection.close
        @log.info {"Connection closed from port #{local_port}"}
        @log.close
      end
      # here we close the parent's copy of the connection --
      # the child (created by the Process::fork above) has another copy --
      # if this one is not closed, when the child closes it's copy,
      # the child's copy won't send a FIN to the client -- the FIN
      # is only sent when the last process holding a copy to the
      # socket closes it's copy
      connection.close
    end
  end

  def main
    $db = nil # in case no DB is opened
    @log = nil # in case error occurs before the log is opened

    # if ssltransportagent was started as root, make sure UserName and
    # GroupName have values because we have to drop root privileges
    # after we fork a process for the receiver
    if Process::Sys.getuid==0
      if UserName.nil? || GroupName.nil?
        puts "ssltransportagent can't be started as root unless UserName and GroupName are set."
        exit(1)
      end
    end

    # get the certificate, if any--a certificate is needed for STARTTLS
    $prv = if PrivateKey then OpenSSL::PKey::RSA.new File.read(PrivateKey) else nil end
    $crt = if Certificate then OpenSSL::X509::Certificate.new File.read(Certificate) else nil end

    # get setup and open the log
    @log = Logger::new(LogPathAndFile, LogFileLife)
    @log.formatter = proc do |severity, datetime, progname, msg|
      pname = if progname then '('+progname+') ' else nil end
      "#{datetime.strftime("%Y-%m-%d %H:%M:%S")} [#{severity}] #{pname}#{msg}\n"
    end
    @log.info {"Starting RubyTA at #{Time.now.strftime("%Y-%m-%d %H:%M:%S %Z")}"}

    # open the database, if any is required
    $db = if Host[:host] then Mysql2::Client.new(Host) else nil end
    db_open if defined?(db_open)

    # this is the main loop which runs until admin enters ^C
    Signal.trap("INT") { puts "\n#{ServerName} terminated by admin ^C"; raise TATerminate.new }
    Signal.trap("HUP") { puts "\n#{ServerName} received a HUP request"; restart if defined?(restart) }
    Signal.trap("CHLD") { Process.wait(-1, Process::WNOHANG) }
    threads = []
    # start the server on multiple ports (the usual case)
    begin
      ListeningPort.each do |port|
        threads << Thread.start(port) do |port|
          listening_thread(port)
        end
      end
      # the joins are done ONLY after all threads are started
      threads.each { |thread| thread.join }
    rescue TATerminate
      # nothing to do here
    end

    # close the database and log
    db_close if defined?(db_close)
    $db.close if $db
    @log.close if @log
  end

end

class TAReceiver

  CRLF = "\r\n"

  include ServerConfig
  include ReceiverConfig
  
  # save the log and connection, then yield back
  # this method assured that the connection gets closed
  def initialize(log, connection)
    @log = log
    @connection = connection
    yield(self)
    connection.close
  end

  # send text to the client
  def send_text(text,echo=true)
    if text.class==Array
      text.each do |line|
        @connection.write(line+CRLF)
#puts "<-  #{line}"
        @log.info {"<-  #{line}"} if echo
      end
      return text.last
    else
      @connection.write(text+CRLF)
#puts "<-  #{text}"
      @log.info {"<-  #{text}"} if echo
      return nil
    end
  end

  # receive text from the client
  def recv_text(echo=true)
    begin
      Timeout.timeout(ReceiverTimeout) do
        temp = @connection.gets
        text = if temp.nil? then nil else temp.chomp end
#puts " -> #{text}"
        @log.info {" -> #{if text.nil? then "<eod>" else text end}"} if echo
        return (if text.nil? then nil else text.chomp end)
      end
    rescue Timeout::Error => e
      @log.info {" -> <eod>"}
      return nil
    end
  end

end
