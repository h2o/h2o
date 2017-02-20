# Travis CI Status [![Build Status](https://travis-ci.org/deweerdt/h2get.svg?branch=master)](https://travis-ci.org/deweerdt/h2get)

# Ruby API

## H2 object

### H2.new

Creates a new `H2` object

### H2.connect(url)

Connects to a URL (only https is implemented currently)

### H2.send_prefix()

Sends the HTTP/2 connection prefix

### H2.send_settings()

Sends an SETTINGS frame

### H2.send_settings_ack()

Sends a SETTINGS frame with the ack flag

### H2.send_priority()

Send a PRIORITY frame


### H2.send_window_update(sid, increment)

Send a WINDOW_UPDATE frame

### H2.get(path)

Sends a HEADER frame

### H2.getp(path)

Sends a HEADER frame with priority information

### H2.read(timeout)

Reads a Frame, or times out. Returns nil on timeout

## Frame object

### Frame.type

Returns a string representation of the frame type

### Frame.type_num

Returns a numeric representation of the frame type

### Frame.to_s

Returns a text representation of a frame


### Frame.flags

Returns the frame flags field

### Frame.len

Returns the length of the frame's payload

### Frame.is_end_stream

Returns true if the `END_STREAM` flag is set

### Frame.stream_id

Returns the length of the frame's stream_id

### Frame.ack()

For types that support it (`PING`, `SETTINGS`) send a ack frame

## Priority object

### Priority.new(dependent_sid, exclusive, weight)

Creates a new priority object (to be used with H2.getp)

