#!/usr/bin/env python3
#
# Copyright (c) 2020 Fastly, Toru Maesaka
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import sys
import json

PACKET_LABELS = ["initial", "0rtt", "handshake", "1rtt"]

def handle_packet_lost(events, idx):
    return [events[idx]["time"], "recovery", "packet_lost", {
        "packet_type": PACKET_LABELS[events[idx]["packet-type"]],
        "header": {
            "packet_number": events[idx]["pn"]
        }
    }]

def handle_packet_received(events, idx):
    frames = []
    acked = []
    for i in range(idx+1, len(events)):
        ev = events[i]
        if ev["type"] == "packet-prepare" or ev["type"] in QLOG_EVENT_HANDLERS:
            break

        # An ACK frame can't be re-composed in an iteration. Continue buffering
        # the ACK blocks until all the blocks are processed.
        if ev["type"] == "ack-block-received":
            acked.append([ev["ack-block-begin"],ev["ack-block-end"]])
            continue
        elif ev["type"] == "ack-delay-received":
            frames.append(render_ack_frame(acked))
            continue

        handler = FRAME_EVENT_HANDLERS.get(ev["type"])
        if handler:
            frames.append(handler(ev))

    return [events[idx]["time"], "transport", "packet_received", {
        "packet_type": PACKET_LABELS[events[idx]["packet-type"]],
        "header": {
            "packet_number": events[idx]["pn"]
        },
        "frames": frames
    }]

def handle_packet_sent(events, idx):
    frames = []
    i = idx-1
    while i > 0 and events[i]["type"] != "packet-prepare":
        handler = FRAME_EVENT_HANDLERS.get(events[i]["type"])
        if handler:
            frames.append(handler(events[i]))
        i -= 1

    return [events[idx]["time"], "transport", "packet_sent", {
        "packet_type": PACKET_LABELS[events[idx]["packet-type"]],
        "header": {
            "packet_number": events[idx]["pn"]
        },
        "frames": frames
    }]

def handle_ack_send(event):
    return render_ack_frame([[event["largest-acked"]]])

def handle_data_blocked_receive(event):
    return {
        "frame_type": "data_blocked"
    }

def handle_data_blocked_send(event):
    return {
        "frame_type": "data_blocked"
    }

def handle_handshake_done_receive(event):
    return {
        "frame_type": "handshake_done",
    }

def handle_handshake_done_send(event):
    return {
        "frame_type": "handshake_done",
    }

def handle_max_data_receive(event):
    return {
        "frame_type": "max_data",
        "maximum": event["maximum"]
    }

def handle_max_data_send(event):
    return {
        "frame_type": "max_data",
        "maximum": event["maximum"]
    }

def handle_max_streams_send(event):
    if event["is-unidirectional"]:
        stream_type = "unidirectional"
    else:
        stream_type = "bidirectional"
    return {
        "frame_type": "max_streams",
        "stream_type": stream_type,
        "maximum": event["maximum"]
    }

def handle_max_stream_data_receive(event):
    return {
        "frame_type": "max_stream_data",
        "stream_id": event["stream-id"],
        "maximum": event["maximum"]
    }

def handle_max_stream_data_send(event):
    return {
        "frame_type": "max_stream_data",
        "stream_id": event["stream-id"],
        "maximum": event["maximum"]
    }

def handle_new_connection_id_receive(event):
    return {
        "frame_type": "new_connection_id",
        "sequence_number": event["sequence"],
        "retire_prior_to": event["retire-prior-to"],
        "connection_id": event["cid"],
        "stateless_reset_token": event["stateless-reset-token"]
    }

def handle_new_connection_id_send(event):
    return {
        "frame_type": "new_connection_id",
        "sequence_number": event["sequence"],
        "retire_prior_to": event["retire-prior-to"],
        "connection_id": event["cid"],
        "stateless_reset_token": event["stateless-reset-token"]
    }

def handle_new_token_receive(event):
    return {
        "frame_type": "new_token",
        "token": event["token"],
        "generation": event["generation"]
    }

def handle_new_token_send(event):
    return {
        "frame_type": "new_token",
        "token": event["token"],
        "generation": event["generation"]
    }

def handle_ping_receive(event):
    return {
        "frame_type": "ping",
    }

def handle_retire_connection_id_receive(event):
    return {
        "frame_type": "retire_connection_id",
        "sequence_number": event["sequence"]
    }

def handle_retire_connection_id_send(event):
    return {
        "frame_type": "retire_connection_id",
        "sequence_number": event["sequence"]
    }

def handle_stream_data_blocked_receive(event):
    return {
        "frame_type": "stream_data_blocked",
        "stream_id": event["stream-id"],
        "maximum": event["maximum"]
    }

def handle_stream_data_blocked_send(event):
    return {
        "frame_type": "stream_data_blocked",
        "stream_id": event["stream-id"],
        "maximum": event["maximum"]
    }

def handle_stream_on_receive_reset(event):
    return {
        "frame_type": "reset_stream",
        "stream_id": event["stream-id"],
        "error_code": event["err"]
    }

def handle_stream_receive(event):
    label = "stream" if event["stream-id"] >= 0 else "crypto"
    return {
        "frame_type": label,
        "stream_id": event["stream-id"],
        "length": event["len"],
        "offset": event["off"]
    }

def handle_stream_send(event):
    label = "stream" if event["stream-id"] >= 0 else "crypto"
    return {
        "frame_type": label,
        "stream_id": event["stream-id"],
        "length": event["len"],
        "offset": event["off"]
    }

def handle_stream_on_send_stop(event):
    return {
        "frame_type": "stop_sending",
        "stream_id": event["stream-id"]
    }

def handle_streams_blocked_receive(event):
    if event["is-unidirectional"]:
      stream_type = "unidirectional"
    else:
      stream_type = "bidirectional"
    return {
        "frame_type": "streams_blocked",
        "stream_type": stream_type,
        "maximum": event["maximum"]
    }

def handle_streams_blocked_send(event):
    if event["is-unidirectional"]:
      stream_type = "unidirectional"
    else:
      stream_type = "bidirectional"
    return {
        "frame_type": "streams_blocked",
        "stream_type": stream_type,
        "maximum": event["maximum"]
    }

def handle_transport_close_receive(event):
    return {
        "frame_type": "connection_close",
        "offending_frame_type": event["frame-type"],
        "error_code": event["error-code"],
        "reason": event["reason-phrase"]
    }

def handle_transport_close_send(event):
    return {
        "frame_type": "connection_close",
        "offending_frame_type": event["frame-type"],
        "error_code": event["error-code"],
        "reason": event["reason-phrase"]
    }

def render_ack_frame(ranges):
    return {
        "frame_type": "ack",
        "acked_ranges": ranges
    }

QLOG_EVENT_HANDLERS = {
    "packet-lost": handle_packet_lost,
    "packet-received": handle_packet_received,
    "packet-sent": handle_packet_sent
}

FRAME_EVENT_HANDLERS = {
    "ack-send": handle_ack_send,
    "data-blocked-receive": handle_data_blocked_receive,
    "data-blocked-send": handle_data_blocked_send,
    "handshake-done-receive": handle_handshake_done_receive,
    "handshake-done-send": handle_handshake_done_send,
    "max-data-receive": handle_max_data_receive,
    "max-data-send": handle_max_data_send,
    "max-streams-send": handle_max_streams_send,
    "max-stream-data-receive": handle_max_stream_data_receive,
    "max-stream-data-send": handle_max_stream_data_send,
    "new-connection-id-receive": handle_new_connection_id_receive,
    "new-connection-id-send": handle_new_connection_id_send,
    "new-token-receive": handle_new_token_receive,
    "new-token-send": handle_new_token_send,
    "ping-receive": handle_ping_receive,
    "retire-connection-id-receive": handle_retire_connection_id_receive,
    "retire-connection-id-send": handle_retire_connection_id_send,
    "stream-data-blocked-receive": handle_stream_data_blocked_receive,
    "stream-data-blocked-send": handle_stream_data_blocked_send,
    "stream-on-receive-reset": handle_stream_on_receive_reset,
    "stream-send": handle_stream_send,
    "streams-blocked-receive": handle_streams_blocked_receive,
    "streams-blocked-send": handle_streams_blocked_send,
    "stream-on-send-stop": handle_stream_on_send_stop,
    "stream-receive": handle_stream_receive,
    "transport-close-receive": handle_transport_close_receive,
    "transport-close-send": handle_transport_close_send
}

def usage():
    print(r"""
Usage:
    python qlog-adapter.py inTrace.jsonl
""".strip())

def load_quicly_events(infile):
    events = []
    with open(infile, "r") as fh:
        for line in fh:
            events.append(json.loads(line))
    return events

def main():
    if len(sys.argv) != 2:
        usage()
        sys.exit(1)

    (_, infile) = sys.argv
    source_events = load_quicly_events(infile)
    trace = {
        "vantage_point": {
            "type": "server"
        },
        "event_fields": [
           "time",
           "category",
           "event",
           "data"
        ],
        "events": []
    }
    for i, event in enumerate(source_events):
        handler = QLOG_EVENT_HANDLERS.get(event["type"])
        if handler:
            trace["events"].append(handler(source_events, i))

    print(json.dumps({
        "qlog_version": "draft-02-wip",
        "title": "h2o/quicly qlog",
        "traces": [trace]
    }))

if __name__ == "__main__":
    main()
