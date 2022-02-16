FROM h2oserver/h2o-ci:ubuntu2004 as builder

USER root
WORKDIR /

RUN apt-get update && \
  apt-get install -y net-tools iputils-ping tcpdump ethtool iperf

# build with --build-arg CACHEBUST=$(date +%s)
ARG CACHEBUST=1

# quicly
RUN git clone https://github.com/h2o/quicly.git

RUN cd quicly &&  git pull && git submodule update --init --recursive && cmake . && make


FROM martenseemann/quic-network-simulator-endpoint:latest

COPY --from=builder /quicly/cli quicly/cli

# endpoint
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
