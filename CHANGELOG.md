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
