FROM h2oserver/h2o-ci:ubuntu2004 as builder

USER root
WORKDIR /h2o

RUN apt-get update && \
  apt-get install -y net-tools iputils-ping tcpdump ethtool iperf

# build with --build-arg CACHEBUST=$(date +%s)
ARG CACHEBUST=1

COPY . .

RUN cmake . && make quicly-cli

FROM martenseemann/quic-network-simulator-endpoint:latest

COPY --from=builder /h2o/quicly/cli /quicly/cli

# endpoint
COPY --from=builder /h2o/misc/quic-interop-runner/run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
