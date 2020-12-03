# Generates trace files with sent packet and ack information from quicly log.
import sys
import json

def find_cids(f):
    cids = {}
    for line in f:
        event = json.loads(line)
        if event["type"] == "": continue
        cids[event["conn"]] = None
    return cids


def gen_trace(f, cid, sent_trace, ack_trace):
    conn_start = 0
    for line in f:
        event = json.loads(line)
        if event["type"] == "" or event["conn"] != cid: continue

        # sent packet
        if event["type"] == "packet-sent":
            if conn_start == 0: conn_start = event["time"]
            outstr = str(event["time"] - conn_start) + " " + \
                str(event["pn"]) + " " + \
                str(event["len"])
            sent_trace.write(outstr + "\n")

        # received ack
        if event["type"] == "packet-acked":
            outstr = str(event["time"] - conn_start) + " " + \
                str(event["pn"])
            ack_trace.write(outstr + "\n")
            

def main():
    if len(sys.argv) == 2:
        print "Connection IDs:", find_cids(open(sys.argv[1], 'r')).keys()
        return 1
    elif len(sys.argv) != 3:
        print "Usage: python parselog.py logfile [connection_id]"
        return 0

    f = open(sys.argv[1], 'r')
    cid = int(sys.argv[2])
    sent_trace = open("trace." + str(cid) + ".str", 'w')
    ack_trace = open("trace." + str(cid) + ".atr", 'w')
    gen_trace(f, cid, sent_trace, ack_trace)
    f.close()
    sent_trace.close()
    ack_trace.close()


main()
