#!/bin/bash

# Set up the routing needed for the simulation.
/setup.sh
cd quicly

if [ ! -z "$TESTCASE" ]; then
    case "$TESTCASE" in
        "handshake"|"transfer"|"retry"|"goodput"|"resumption"|"multiconnect") ;;
        "http3") exit 127 ;;
        *) exit 127 ;;
    esac
fi

### Client side ###
if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    cd /downloads
    case "$TESTCASE" in
        "resumption") TEST_PARAMS="-s previous_sessions.bin" ;;
        *) ;;
    esac
    echo "Starting quicly client ..."
    if [ ! -z "$REQUESTS" ]; then
        echo "Requests: " $REQUESTS
        # Pull server and file names out of requests, generate file list for cli.
        for REQ in $REQUESTS; do
            SERVER=`echo $REQ | cut -f3 -d'/' | cut -f1 -d':'`
            FILE=`echo $REQ | cut -f4 -d'/'`
            FILES=${FILES}" "${FILE}
            CLI_LIST=${CLI_LIST}" -P /"${FILE}
        done

        if [ "$TESTCASE" == "resumption" ]; then
            # Client needs to be run twice. First, with one request.
            FILE=`echo $FILES | cut -f1 -d" "`
            echo "/quicly/cli -P /$FILE $SERVER 443"
            /quicly/cli -P "/"$FILE $TEST_PARAMS -a "hq-29" -x x25519 -x secp256r1 -e /logs/$TESTCASE.out $SERVER 443

            # Second time, with rest of the requests.
            CLI_LIST=`echo $CLI_LIST | cut -f3- -d" "`
            echo "/quicly/cli $CLI_LIST $SERVER 443"
            /quicly/cli $CLI_LIST $TEST_PARAMS -a "hq-29" -x x25519 -x secp256r1 -e /logs/$TESTCASE.out $SERVER 443
            rm -f previous_sessions.bin

        elif [ "$TESTCASE" == "multiconnect" ]; then
            # Client needs to be run once per file.
            for FILE in $FILES; do
                echo "/quicly/cli /$FILE $SERVER 443"
                /quicly/cli -P "/"$FILE $TEST_PARAMS -a "hq-29" -x x25519 -x secp256r1 -e /logs/$TESTCASE.out $SERVER 443
            done

        else
            # Client is run once for all files.
            echo "/quicly/cli $CLI_LIST $SERVER 443"
            /quicly/cli $CLI_LIST $TEST_PARAMS -a "hq-29" -x x25519 -x secp256r1 -e /logs/$TESTCASE.out $SERVER 443
        fi

        # Cleanup.
        for FILE in $FILES; do
            mv $FILE.downloaded $FILE
        done
    fi

### Server side ###
elif [ "$ROLE" == "server" ]; then
    echo "Starting server for test:" $TESTCASE
    echo "Serving files:"
    cd /www && ls -l
    case "$TESTCASE" in
        "retry") TEST_PARAMS="-R" ;;
        *) ;;
    esac
    echo "Starting quicly server ..."
    echo "SERVER_PARAMS:" $SERVER_PARAMS "TEST_PARAMS:" $TEST_PARAMS
    echo "/quicly/cli $SERVER_PARAMS $TEST_PARAMS -k /certs/priv.key -c /certs/cert.pem -e /logs/$TESTCASE.out 0.0.0.0 443"
    /quicly/cli $SERVER_PARAMS $TEST_PARAMS -k /certs/priv.key -c /certs/cert.pem -x x25519 -x secp256r1 -a "hq-29" -e /logs/$TESTCASE.out 0.0.0.0 443
fi
