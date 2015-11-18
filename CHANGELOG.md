# v1.09
* Fixed a naming error. (log --> @log)

# v1.08
* Added a rescue for Errno::ECONNRESET which is usually caused by a badly-behaved client. "Connection reset by peer" is the TCP/IP equivalent of slamming the phone down on the hook. It's more polite than merely not replying, leaving one hanging, but it's not the FIN-ACK expected of the truly polite TCP/IP conversation.
* Removed `set_mail_id` and replaced it with the Process::pid in parenthesis ater the log level. This is because one needs to know which message is part of a set when more than one process is adding messages to the log. In this example,
```
2015-11-13 03:58:11 [INFO] (022999) Connection accepted on port 25 from port 33402 at ::ffff:166.78.151.141 (rubymta-test)
2015-11-13 03:58:11 [WARN] (023004) Connection failure on port 587 ignored; may be caused by a port scan
2015-11-13 03:58:11 [INFO] (022999) MySQL database czar_development opened on localhost by czar
2015-11-13 03:58:11 [INFO] (022999) Receiving message id: 1Zx5V5-1Kefa1-C4
```
there is a message for PID 023004 mixed in with the messages for PID 022999.

# v1.07
* Rescues added for two errors caused by client closing port early.
* Corrected some text in a comment.
* Removed a piece of duplicated code.
* Added options parser. The options are:
(1) `--debug`, `--info`, `--warn`, `--error`, or `--fatal` to control the logging of messages. The default is `--info`.
(2) `--daemon` to start the server as an unattended process.
* The pid is stored in `/run/ssltransportagent/ssltransportagent.pid`. You must create the folder `/run/ssltransportagent` with permissions for the user under whom the ssltransportagent will be running; otherwise, ssltransportagent will still run, but the pid won't be stored. The server will try to remove the pid file upon exit, but if KILL -TERM or a similar kill command is used, the server will be stopped before it can "clean itself up". Always use `kill -INT <pid>` or `^C` to stop the server.
* Added `set_mail_id(id)` to allow setting the parameter in calls to the logger. See README.md for more information.

# v1.06
* Added rescues for Errno::EIO and Error::EPIPE which are caused by the client closing the port while the server is reading or writing it. This happens when the client closes it's port unexpectedly.

# v1.05
* Added a rescue for Errno::ENOTCONN which is caused by a port scan.

# v1.04
* Still had some problems with `bind_socket`. Changed the default for a lone port number `['2000']` to be `['0:0:0:0:0:0:0:0/2000]` which will start listening on both IPv4 and IPv6 on port 2000.

# v1.03
* The parameters got reversed on `bind_socket` in `ssltransportagent`. Fixed.

# v1.02
* Modified ssltransportagent.rb to permit an IP address with the port number to bind the port to that IP. Also added support for IPV6 as well as IPV4. A `require 'etc'` was left off the previous versions, and was added here. It's needed in order to use ports under 1024 (i.e, 25 and 587 for SMTP, or 24 for Dovecot LMTP, for example).

# v1.01
* A fault was discovered in validate_plain which failed when a nil was returned in the yield asking for the password.

# v1.0
* This version has been tested by sending over 23,000 emails received from spammers to it. There were no faults detected. This version is considered a stable release.
* Removed the message in the SIGHUP trap.
 
If you want a message, define
```ruby
class TAServer
  def restart
    puts "MyMailServer received a HUP request"
  end
end
```
But typically, you would silently restart like this:
```ruby
class TAServer
  def restart
    exec("ruby <path to your application>")
  end
end
```
The running server will be shutdown and restarted, replacing the current image with the new image in the same PID. Emails in the process of being received are in child processes and will continue to run and finish as normal.

A message will be added to the log file showing that the server was (re)started. If the application is running as a deamon, there won't be a terminal to write to anyway, unless the system traps the output and emails it to you (in the same way crontab handles terminal output).

# v0.9
* Added a trap for Resolv::NXDomainError in blacklisted?"

# v0.8
* Added a trap to catch Errno::ECHILD in the trap("CHLD").

# v0.7
* Added a configuration variable to control the logging of the conversation. Normally you don't want to see this because it has no useful function, other than for debugging.

# v0.6
* Added a trap for SIGCHLD to clean up finished processes.

# v0.5
* Added `blacklisted?` and `utf8` methods. See README.
* Added a `log.close` statement to close the child's connection to the log after the child exits.
* Added a HUP trap for doing a restart without stopping the application.

# v0.4
* Changed `validate_plain` to return the username and the (true/false) result. This change was necessary to obtain the username for log messages.

# v0.3
* Changed send_text to add an `echo` parameter. This, and the `echo` in recv_text allow the application to avoid logging long runs of data, such as a large email with significant text or coded binary.

# v0.2
* Changed the send_text method to return nil. This change was needed for SMTP Tranport Agent that uses this gem.

# v0.1
This is the initial load of the gem. All functions appear to be working, but the gem is not yet in production, so there is a probability that other as yet untested cases will cause failures.
