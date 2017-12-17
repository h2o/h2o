FROM ubuntu:16.04

RUN apt-get --yes update
RUN apt-get install --yes libterm-readline-perl-perl # suppress bogus warnings on travis

# huge packages go first (for better cacheability)
RUN apt-get install --yes bison ruby-dev
RUN apt-get install --yes php-cgi

# tools for building and testing
RUN apt-get install --yes apache2-utils cmake cmake-data git memcached netcat-openbsd nghttp2-client redis-server wget
RUN apt-get install --yes libev-dev libc-ares-dev libnghttp2-dev libssl-dev libuv1-dev zlib1g-dev

# cpan modules
RUN apt-get install --yes cpanminus
RUN apt-get install --yes libfcgi-perl libfcgi-procmanager-perl libipc-signal-perl libjson-perl liblist-moreutils-perl libplack-perl libscope-guard-perl libtest-exception-perl libtest-tcp-perl libwww-perl libio-socket-ssl-perl starlet

# create user
RUN apt-get install --yes sudo
RUN useradd --create-home ci
RUN echo 'ci ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
WORKDIR /home/ci
USER ci

# custom builds
RUN wget --no-verbose -O - https://curl.haxx.se/download/curl-7.57.0.tar.gz | tar xzf -
RUN (cd curl-7.57.0 && ./configure --prefix=/usr/local --with-nghttp2 --disable-shared && make && sudo make install)
