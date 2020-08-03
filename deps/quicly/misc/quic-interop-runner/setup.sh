#!/bin/bash

echo "Setting up routes..."
# By default, docker containers don't compute UDP / TCP checksums.
# When packets run through ns3 however, the receiving endpoint requires valid checksums.
# This command makes sure that the endpoints set the checksum on outgoing packets.
ethtool -K eth0 tx off

IP=`hostname -I`
GATEWAY="${IP%.*}.2"
UNNEEDED_ROUTE="${IP%.*}.0"

echo "193.167.0.100 client" >> /etc/hosts
echo "193.167.100.100 server" >> /etc/hosts

route add -net 193.167.0.0 netmask 255.255.0.0 gw $GATEWAY
# delete unused route
route del -net $UNNEEDED_ROUTE netmask 255.255.255.0

# create the logs directory
mkdir /logs
