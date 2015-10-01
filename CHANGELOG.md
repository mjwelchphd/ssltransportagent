# v0.3
* Changed send_text to add an `echo` parameter. This, and the `echo` in recv_text allow the application to avoid logging long runs of data, such as a large email with significant text or coded binary.

# v0.2
* Changed the send_text method to return nil. This change was needed for SMTP Tranport Agent that uses this gem.

# v0.1
This is the initial load of the gem. All functions appear to be working, but the gem is not yet in production, so there is a probability that other as yet untested cases will cause failures.
