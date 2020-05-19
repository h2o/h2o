FROM ubuntu:16.04

RUN apt-get --yes update

# huge packages go first (for better cacheability)
RUN apt-get install --yes bison ruby-dev
RUN apt-get install --yes php-cgi

# tools for building and testing
RUN apt-get install --yes apache2-utils cmake cmake-data git memcached netcat-openbsd nghttp2-client redis-server wget sudo
RUN apt-get install --yes libev-dev libc-ares-dev libnghttp2-dev libssl-dev libuv1-dev zlib1g-dev libbrotli-dev

# clang-4.0 for fuzzing
RUN apt-get install -y clang-4.0
ENV PATH=/usr/lib/llvm-4.0/bin:$PATH

# curl with http2 support
RUN wget --no-verbose -O - https://curl.haxx.se/download/curl-7.57.0.tar.gz | tar xzf -
RUN (cd curl-7.57.0 && ./configure --prefix=/usr/local --with-nghttp2 --disable-shared && make && sudo make install)

ARG OPENSSL_URL="https://www.openssl.org/source/"
# openssl 1.1.0
ARG OPENSSL_VERSION="1.1.0i"
ARG OPENSSL_SHA1="6713f8b083e4c0b0e70fd090bf714169baf3717c"
RUN curl -O ${OPENSSL_URL}openssl-${OPENSSL_VERSION}.tar.gz
RUN (echo "${OPENSSL_SHA1} openssl-${OPENSSL_VERSION}.tar.gz" | sha1sum -c - && tar xf openssl-${OPENSSL_VERSION}.tar.gz)
RUN (cd openssl-${OPENSSL_VERSION} && \
	./config --prefix=/opt/openssl-1.1.0 --openssldir=/opt/openssl-1.1.0 shared enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers && \
	make -j $(nproc) && make -j install_sw install_ssldirs)

# openssl 1.1.1
ARG OPENSSL_VERSION="1.1.1c"
ARG OPENSSL_SHA1="71b830a077276cbeccc994369538617a21bee808"
RUN curl -O ${OPENSSL_URL}openssl-${OPENSSL_VERSION}.tar.gz
RUN (echo "${OPENSSL_SHA1} openssl-${OPENSSL_VERSION}.tar.gz" | sha1sum -c - && tar xf openssl-${OPENSSL_VERSION}.tar.gz)
RUN (cd openssl-${OPENSSL_VERSION} && \
	./config --prefix=/opt/openssl-1.1.1 --openssldir=/opt/openssl-1.1.1 shared enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers && \
	make -j $(nproc) && make -j install_sw install_ssldirs)

# cpan modules
RUN apt-get install --yes cpanminus
RUN apt-get install --yes libfcgi-perl libfcgi-procmanager-perl libipc-signal-perl libjson-perl liblist-moreutils-perl libplack-perl libscope-guard-perl libtest-exception-perl libwww-perl libio-socket-ssl-perl
ENV PERL_CPANM_OPT="--mirror https://cpan.metacpan.org/"
RUN sudo cpanm --notest Starlet Protocol::HTTP2

# Test-TCP 2.21
RUN sudo cpanm --notest https://github.com/tokuhirom/Test-TCP.git@2.21
# h2spec
RUN curl -Ls https://github.com/i110/h2spec/releases/download/v2.2.0-4e8cc7e/h2spec_linux_amd64.tar.gz | tar zx -C /usr/local/bin

# h2load
ARG NGHTTP2_VERSION="1.30.0"
ARG NGHTTP2_SHA256="089afb4c22a53f72384b71ea06194be255a8a73b50b1412589105d0e683c52ac"
RUN apt-get install --yes autoconf automake autotools-dev libtool pkg-config
RUN curl -LO https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VERSION}/nghttp2-${NGHTTP2_VERSION}.tar.xz
RUN (echo "${NGHTTP2_SHA256} nghttp2-${NGHTTP2_VERSION}.tar.xz" | sha256sum -c -)
RUN tar xf nghttp2-${NGHTTP2_VERSION}.tar.xz
RUN cd nghttp2-${NGHTTP2_VERSION} && autoreconf -i && automake && autoconf && ./configure --enable-app --prefix=/usr/local && make && make install
ENV LD_LIBRARY_PATH="/usr/local/lib"

# use dumb-init
RUN wget -O /usr/local/bin/dumb-init https://github.com/Yelp/dumb-init/releases/download/v1.2.1/dumb-init_1.2.1_amd64 \
 && chmod +x /usr/local/bin/dumb-init

# create user
RUN useradd --create-home ci
RUN echo 'ci ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
WORKDIR /home/ci
USER ci

ENTRYPOINT ["/usr/local/bin/dumb-init"]
