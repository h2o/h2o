FROM ubuntu:16.04

RUN apt-get --yes update

# huge packages go first (for better cacheability)
RUN apt-get install --yes bison ruby-dev
RUN apt-get install --yes php-cgi

# tools for building and testing
RUN apt-get install --yes apache2-utils cmake cmake-data git memcached netcat-openbsd nghttp2-client redis-server wget sudo
RUN apt-get install --yes libev-dev libc-ares-dev libnghttp2-dev libssl-dev libuv1-dev zlib1g-dev

# cpan modules
RUN apt-get install --yes cpanminus
RUN apt-get install --yes libfcgi-perl libfcgi-procmanager-perl libipc-signal-perl libjson-perl liblist-moreutils-perl libplack-perl libscope-guard-perl libtest-exception-perl libtest-tcp-perl libwww-perl libio-socket-ssl-perl starlet

# clang-4.0 for fuzzing
RUN apt-get install -y clang-4.0

# configuration
RUN echo '127.0.0.1 127.0.0.1.xip.io' >> /etc/hosts

# create user
RUN useradd --create-home ci
RUN echo 'ci ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
WORKDIR /home/ci
USER ci

# custom builds
RUN wget --no-verbose -O - https://curl.haxx.se/download/curl-7.57.0.tar.gz | tar xzf -
RUN (cd curl-7.57.0 && ./configure --prefix=/usr/local --with-nghttp2 --disable-shared && make && sudo make install)
