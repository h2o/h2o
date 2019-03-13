import sys
import json
import base64
from pprint import pprint

epoch = ["ENCRYPTION_INITIAL", "ENCRYPTION_0RTT", "ENCRYPTION_UNKNOWN", "ENCRYPTION_1RTT"]

def transform(inf, outf):
    start = -1
    cid = -1
    qtr = {}
    qtr["protocolVersion"] = "AAAA"
    qtr["events"] = []
    packet = {}
    sframes = []
    rframes = []
    state = {}

    for line in inf:
        trace = json.loads(line)
        if len(trace["type"]) < 11 or trace["type"][:9] != "quictrace": continue

        # use first connection that is seen as the CID for the trace.
        # TODO: make this a cmdline parameter if multiple CIDs in trace.
        if cid == -1: 
            cid = trace["conn"]
            qtr["destinationConnectionId"] = base64.b64encode(str(cid))

        event = trace["type"][10:]

        if event == "sent" or event == "recv" or event == "lost":
            # if last loss was not posted, do it now (TSNH)
            if packet and packet["eventType"] == "PACKET_LOST":
               qtr["events"].append(packet)
               packet = {}
               print "WARNING: Packet lost but no transport state posted"

            # close out previous received packet if it's still open
            if rframes:
                packet = {}
                packet["eventType"] = "PACKET_RECEIVED"
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
        if event == "recv-ack":
            if "ack-delay" not in trace:
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
        packet["timeUs"] = str((rtime - start) * 1000)
        packet["packetNumber"] = str(rpn)
        packet["frames"] = rframes
        packet["transportState"] = state
        qtr["events"].append(packet)

    # finished processing
    json.dump(qtr, outf)


def main():
    if len(sys.argv) != 3:
        print "Usage: python adapter.py inTrace outTrace"
        sys.exit(1)
        
    inf = open(sys.argv[1], 'r')
    outf = open(sys.argv[2], 'w')
    transform(inf, outf)
    inf.close()
    outf.close()


if __name__ == "__main__":
    main()

