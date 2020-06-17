#!/usr/bin/env python
from __future__ import print_function
import sys
import json
import base64
import time
import os
from collections import OrderedDict
from pprint import pprint

def usage():
    print(r"""
Usage:
    quictrace-adapter.py inTrace.jsonl outTrace.json cid
    quictrace-adatper.py inTrace.jsonl outTraceDir
""".strip())


epoch = ["ENCRYPTION_INITIAL", "ENCRYPTION_0RTT", "ENCRYPTION_HANDSHAKE", "ENCRYPTION_1RTT"]

def transform(inf, outf, cid):
    start = -1
    qtr = {}
    qtr["protocolVersion"] = "AAAA"
    qtr["destinationConnectionId"] = base64.b64encode(str(cid))
    qtr["events"] = []
    packet = {}
    sframes = []
    rframes = []
    state = {}

    for line in inf:
        if line[0] != "{":
            continue
        trace = json.loads(line)
        type = trace["type"]
        if len(type) < 11 or type[:9] != "quictrace" or trace["conn"] != cid:
            continue

        event = type[10:]
        if event == "sent" or event == "recv" or event == "lost":
            # if last loss was not posted, do it now (TSNH)
            if packet and packet["eventType"] == "PACKET_LOST":
               qtr["events"].append(packet)
               packet = {}
               # multiple packet losses. TODO: store packet and post after congestion state read.
               # print "WARNING: Packet lost but no transport state posted"

            # close out previous received packet if it's still open
            if rframes:
                packet = {}
                packet["eventType"] = "PACKET_RECEIVED"
                packet["encryptionLevel"] = epoch[3] # hack
                packet["timeUs"] = str((rtime - start) * 1000)
                packet["packetNumber"] = str(rpn)
                packet["frames"] = rframes
                packet["transportState"] = state
                qtr["events"].append(packet)
                # reset state
                packet = {}
                rframes = []
                state = {}

        # packet lost
        if event == "lost":
            # if last loss was not posted, do it now
            if packet and packet["eventType"] == "PACKET_LOST":
                qtr["events"].append(packet)
            # record new loss
            packet = {}
            packet["eventType"] = "PACKET_LOST"
            packet["encryptionLevel"] = epoch[3]
            if start == -1: start = trace["time"]
            packet["timeUs"] = str((trace["time"] - start) * 1000)
            packet["packetNumber"] = str(trace["pn"])
            # don't post yet, wait to read transport state

        # transport state after loss
        if event == "cc-lost" and "eventType" in packet and packet["eventType"] == "PACKET_LOST":
            state = {}
            state["minRttUs"] = str(trace["min-rtt"] * 1000)
            state["smoothedRttUs"] = str(trace["smoothed-rtt"] * 1000)
            state["lastRttUs"] = str(trace["latest-rtt"] * 1000)
            state["inFlightBytes"] = str(trace["inflight"])
            state["cwndBytes"] = str(trace["cwnd"])
            # post last lost packet with state
            packet["transportState"] = state
            qtr["events"].append(packet)
            # reset state
            packet = {}

        # packet send event
        if event == "sent":
            packet = {}
            packet["eventType"] = "PACKET_SENT"
            if start == -1: start = trace["time"]
            packet["timeUs"] = str((trace["time"] - start) * 1000)
            packet["packetNumber"] = str(trace["pn"])
            packet["packetSize"] = str(trace["len"])
            packet["encryptionLevel"] = epoch[trace["packet-type"]]
            packet["frames"] = sframes
            qtr["events"].append(packet)
            # reset state
            packet = {}
            sframes = []  # empty sent frames list

        # STREAM frame sent
        if event == "send-stream":
            info = {}
            info["streamId"] = str(trace["stream-id"])
            if (trace["stream-id"] < 0):
                info["streamId"] = str(31337 + trace["stream-id"])
            if trace["fin"] == 0:
                info["fin"] = False
            else:
                info["fin"] = True
            info["length"] = str(trace["len"])
            info["offset"] = str(trace["off"])
            # create and populate new frame, add to frames list
            frame = {}
            frame["frameType"] = "STREAM"
            frame["streamFrameInfo"] = info
            sframes.append(frame)

        # packet received
        if event == "recv":
            if start == -1: start = trace["time"]
            rtime = trace["time"]
            rpn = trace["pn"]
            rframes = []
            acked = []
            state = {}

        # process ACK frame info
        if "recv-ack" in event:
            if "recv-ack-delay" not in event:
                # create ack block, add to list
                block = {"firstPacket": str(trace["ack-block-begin"]),
                         "lastPacket": str(trace["ack-block-end"])}
                acked.append(block)
                continue
            # "ack-delay" line closes out ACK frame processing
            ack_info = {}
            ack_info["ackDelayUs"]  = str(trace["ack-delay"])
            ack_info["ackedPackets"] = acked
            frame = {}
            frame["frameType"] = "ACK"
            frame["ackInfo"] = ack_info
            rframes.append(frame)

        if event == "cc-ack":
            state = {}
            state["minRttUs"] = str(trace["min-rtt"] * 1000)
            state["smoothedRttUs"] = str(trace["smoothed-rtt"] * 1000)
            state["lastRttUs"] = str(trace["latest-rtt"] * 1000)
            state["inFlightBytes"] = str(trace["inflight"])
            state["cwndBytes"] = str(trace["cwnd"])
            # state["pacingRateBps"] = str(trace[""])

    # close out last received packet if it's still open
    if rframes:
        # packet = {}
        packet["eventType"] = "PACKET_RECEIVED"
        packet["encryptionLevel"] = epoch[3] # hack
        packet["timeUs"] = str((rtime - start) * 1000)
        packet["packetNumber"] = str(rpn)
        packet["frames"] = rframes
        packet["transportState"] = state
        qtr["events"].append(packet)

    # finished processing
    json.dump(qtr, outf)


def find_cids(infile):
    cids = OrderedDict()
    with open(infile, 'r') as f:
        for line in f:
            event = json.loads(line)
            if event["type"] == "accept":
                cids[event["conn"]] = event
    return cids

def mkdir_p(dirname):
    try:
        os.makedirs(dirname)
    except OSError:
        pass

def main():
    if len(sys.argv) == 3:
        (_, infile, outdir) = sys.argv
        for cid, event in find_cids(infile).items():
            timestamp = time.strftime('%FT%TZ', time.gmtime(event["time"] / 1000))
            mkdir_p(outdir)
            outfile = os.path.join(outdir, '{timestamp}-{cid}.json'.format(timestamp=timestamp, cid=cid))
            with open(infile, 'r') as inf, open(outfile, 'w') as outf:
                print("Transforming %s" % outfile, file = sys.stderr)
                transform(inf, outf, int(cid))
    elif len(sys.argv) == 4:
        (_, infile, outfile, cid) = sys.argv
        with open(infile, 'r') as inf, open(outfile, 'w') as outf:
            print("Transforming %s" % outfile, file = sys.stderr)
            transform(inf, outf, int(cid))
    else:
        usage()
        sys.exit(1)


if __name__ == "__main__":
    main()

