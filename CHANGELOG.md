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
