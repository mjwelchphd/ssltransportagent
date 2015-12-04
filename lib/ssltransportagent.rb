require 'openssl'
require 'optparse'
require 'ostruct'
require 'logger'
require 'mysql2'
require 'net/telnet'
require 'resolv'
require 'base64'
require 'etc'
require 'unix_crypt'
require 'socket'
require_relative 'extended_classes'
require_relative 'query_helpers'

class TATerminate < Exception; end
class TAQuit < Exception; end
class TAIncomplete < Exception; end

class TAServer

  include ServerConfig
  include Socket::Constants

  # this is the code executed after the process has been
  # forked and root privileges have been dropped
  def process_call(log, local_port, connection, remote_port, remote_ip, remote_hostname, remote_service)
    begin
      Signal.trap("INT") { } # ignore ^C in the child process
      log.info("%06d"%Process::pid) {"Connection accepted on port #{local_port} from port #{remote_port} at #{remote_ip} (#{remote_hostname})"}
      # open the database, if any is required
      if Host[:host]
        $db = Mysql2::Client.new(Host)
        db_open if defined?(db_open)
        log.info("%06d"%Process::pid) {"MySQL database #{Host[:database]} opened on #{Host[:host]} by #{Host[:username]}"}
      end
      # a new object is created here to provide separation between server and receiver
      # this call receives the email and does basic validation
      TAReceiver::new(log, connection).receive(local_port, Socket::gethostname, remote_port, remote_hostname, remote_ip)
    rescue TAQuit
      # nothing to do here
    ensure
      # close the database
      db_close if defined?(db_close)
      $db.close if $db
      nil # don't return the TAReceiver object
    end
  end

  # this method drops the process's root privileges for security reasons
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

  # both the AF_INET and AF_INET6 families use this DRY method
  def bind_socket(family,port,ip)
    socket = Socket.new(family, SOCK_STREAM, 0)
    sockaddr = Socket.sockaddr_in(port.to_i,ip)
    socket.setsockopt(:SOCKET, :REUSEADDR, true)
    socket.bind(sockaddr)
    socket.listen(0)
    return socket
  end

  # the listening thread is established in this method depending on the ListenPort
  # argument passed to it -- it can be '<ipv6>/<port>', '<ipv4>:<port>', or just '<port>'
  def listening_thread(local_port)
    @log.info("%06d"%Process::pid) {"listening on port #{local_port}..."}

    # establish an SSL context
    $ctx = OpenSSL::SSL::SSLContext.new
    $ctx.key = $prv
    $ctx.cert = $crt
    
    # check the parameter to see if it's valid
    m = /^(([0-9a-fA-F]{0,4}:{0,1}){1,8})\/([0-9]{1,5})|(([0-9]{1,3}\.{0,1}){4}):([0-9]{1,5})|([0-9]{1,5})$/.match(local_port)
    #<MatchData "2001:4800:7817:104:be76:4eff:fe05:3b18/2000" 1:"2001:4800:7817:104:be76:4eff:fe05:3b18" 2:"3b18" 3:"2000" 4:nil 5:nil 6:nil 7:nil>
    #<MatchData "23.253.107.107:2000" 1:nil 2:nil 3:nil 4:"23.253.107.107" 5:"107" 6:"2000" 7:nil>
    #<MatchData "2000" 1:nil 2:nil 3:nil 4:nil 5:nil 6:nil 7:"2000">
    case
      when !m[1].nil? # its AF_INET6
        socket = bind_socket(AF_INET6,m[3],m[1])
      when !m[4].nil? # its AF_INET
        socket = bind_socket(AF_INET,m[6],m[4])
      when !m[7].nil?
        socket = bind_socket(AF_INET6,m[7],"0:0:0:0:0:0:0:0")
      else
        raise ArgumentError.new(local_port)
    end
    ssl_server = OpenSSL::SSL::SSLServer.new(socket, $ctx);

    # main listening loop starts in non-encrypted mode
    ssl_server.start_immediately = false
    loop do
      # we can't use threads because if we drop root privileges on any thread,
      # they will be dropped for all threads in the process--so we have to fork
      # a process here in order that the reception be able to drop root privileges
      # and run at a user level--this is a security precaution
      connection = ssl_server.accept
      Process::fork do
        begin
          drop_root_privileges(UserName,GroupName,WorkingDirectory) if !UserName.nil?
          remote_hostname, remote_service = connection.io.remote_address.getnameinfo
          remote_ip, remote_port = connection.io.remote_address.ip_unpack
          process_call(@log, local_port, connection, remote_port, remote_ip, remote_hostname, remote_service)
        ensure
          # here we close the child's copy of the connection --
          # since the parent already closed it's copy, this
          # one will send a FIN to the client, so the client
          # can terminate gracefully
          connection.close
          @log.info("%06d"%Process::pid) {"Connection closed on port #{local_port} by #{ServerName}"}
          # and finally, close the child's link to the log
          @log.close
        end
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

  # this method parses the command line options
  def process_options
    options = OpenStruct.new
    options.log = Logger::INFO
    options.daemon = false
    begin
      OptionParser.new do |opts|
        opts.on("--debug",  "Log all messages")     { |v| options.log = Logger::DEBUG }
        opts.on("--info",   "Log all messages")     { |v| options.log = Logger::INFO }
        opts.on("--warn",   "Log all messages")     { |v| options.log = Logger::WARN }
        opts.on("--error",  "Log all messages")     { |v| options.log = Logger::ERROR }
        opts.on("--fatal",  "Log all messages")     { |v| options.log = Logger::FATAL }
        opts.on("--daemon", "Run as system daemon") { |v| options.daemon = true }
      end.parse!
    rescue OptionParser::InvalidOption => e
      @log.warn("%06d"%Process::pid) {"#{e.inspect}"}
    end
    options
  end # process_options

  def main
    $db = nil # in case no DB is opened

    # get setup and open the log
    @log = nil # in case error occurs before the log is opened
    @log = Logger::new(LogPathAndFile, LogFileLife)
    @log.formatter = proc do |severity, datetime, progname, msg|
      pname = if progname then '('+progname+') ' else nil end
      "#{datetime.strftime("%Y-%m-%d %H:%M:%S")} [#{severity}] #{pname}#{msg}\n"
    end

    # generate the first log messages
    @log.info("%06d"%Process::pid) {"Starting RubyTA at #{Time.now.strftime("%Y-%m-%d %H:%M:%S %Z")}, pid=#{Process::pid}"}
    @log.info("%06d"%Process::pid) {"Options specified: #{ARGV.join(", ")}"}

    # get the options from the command line
    @options = process_options
    @log.level = @options.log

    # get the certificates, if any; they're needed for STARTTLS
    # we do this before daemonizing because the working folder might change
    $prv = if PrivateKey then OpenSSL::PKey::RSA.new File.read(PrivateKey) else nil end
    $crt = if Certificate then OpenSSL::X509::Certificate.new File.read(Certificate) else nil end

    # daemonize it if the option was set--it doesn't have to be root to daemonize it
    Process::daemon if @options.daemon

    # get the process ID and the user id AFTER demonizing, if that was requested
    pid = Process::pid
    uid = Process::Sys.getuid
    
    @log.info("%06d"%Process::pid) {"Daemonized at #{Time.now.strftime("%Y-%m-%d %H:%M:%S %Z")}, pid=#{pid}, uid=#{uid}"} if @options.daemon

    # store the pid of the server session
    begin
      File.open("/run/ssltransportagent/ssltransportagent.pid","w") { |f| f.write(pid.to_s) }
    rescue Errno::EACCES => e
      @log.warn("%06d"%Process::pid) {"The pid couldn't be written. To save the pid, create a directory '/run/ssltransportagent' with r/w permissions for this user."}
      @log.warn("%06d"%Process::pid) {"Proceeding without writing the pid."}
    end

    # if ssltransportagent was started as root, make sure UserName and
    # GroupName have values because we have to drop root privileges
    # after we fork a process for the receiver
    if uid==0 # it's root
      if UserName.nil? || GroupName.nil?
        @log.error("%06d"%Process::pid) {"ssltransportagent can't be started as root unless UserName and GroupName are set."}
        exit(1)
      end
    end

    # this is the main loop which runs until admin enters ^C
    Signal.trap("INT") { raise TATerminate.new }
    Signal.trap("HUP") { restart if defined?(restart) }
    Signal.trap("CHLD") do
      begin
      Process.wait(-1, Process::WNOHANG)
      rescue Errno::ECHILD => e
        # ignore the error
      end
    end
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
      @log.info("%06d"%Process::pid) {"#{ServerName} terminated by admin ^C"}
    end

    # attempt to remove the pid file
    begin
      File.delete("/run/ssltransportagent/ssltransportagent.pid")
    rescue Errno::ENOENT => e
      @log.warn("%06d"%Process::pid) {"No such file: #{e.inspect}"}
    rescue Errno::EACCES, Errno::EPERM
      @log.warn("%06d"%Process::pid) {"Permission denied: #{e.inspect}"}
    end

    # close the log
    @log.close if @log
  end

end

class TAReceiver

  CRLF = "\r\n"

  include ServerConfig
  include ReceiverConfig
  
  # save the log and connection
  def initialize(log, connection)
    @log = log
    @connection = connection
  end
  
  Unexpectedly = "; probably caused by the client closing the connection unexpectedly"

  # send text to the client
  def send_text(text,echo=true)
    begin
      if text.class==Array
        text.each do |line|
          @connection.write(line+CRLF)
          @log.debug("%06d"%Process::pid) {"<-  #{line}"} if echo && LogConversation
        end
        return text.last
      else
        @connection.write(text+CRLF)
        @log.debug("%06d"%Process::pid) {"<-  #{text}"} if echo && LogConversation
        return nil
      end
    rescue Errno::EPIPE => e
      @log.error("%06d"%Process::pid) {"#{e.to_s}#{Unexpectedly}"}
      raise TAQuit
    rescue Errno::EIO => e
      @log.error("%06d"%Process::pid) {"#{e.to_s}#{Unexpectedly}"}
      raise TAQuit
    end
  end

  # receive text from the client
  def recv_text(echo=true)
    begin
      Timeout.timeout(ReceiverTimeout) do
        begin
          temp = @connection.gets
          if temp.nil?
            @log.warn("%06d"%Process::pid) {"The client abruptly closed the connection"}
            text = nil
          else
            text = temp.chomp
          end
        rescue Errno::ECONNRESET => e
          @log.warn("%06d"%Process::pid) {"The client slammed the connection shut"}
          text = nil
        end
        @log.debug("%06d"%Process::pid) {" -> #{if text.nil? then "<eod>" else text end}"} if echo && LogConversation
        return text
      end
    rescue Errno::EIO => e
      @log.error("%06d"%Process::pid) {"#{e.to_s}#{Unexpectedly}"}
      raise TAQuit
    rescue Timeout::Error => e
      @log.debug("%06d"%Process::pid) {" -> <eod>"} if LogConversation
      return nil
    end
  end

end
