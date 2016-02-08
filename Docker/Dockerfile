#
# Dockerfile for h2o
#

FROM alpine
MAINTAINER Lars K.W. Gohlke <lkwg82@gmx.de>

RUN apk update \
    && apk upgrade \
    # need for ocsp stapling \
    && apk add -U perl openssl \
    && apk add -U build-base \
               cmake \
               curl \
               linux-headers \
               zlib-dev \
               ca-certificates curl wget \
    && wget -O - $(curl -s https://api.github.com/repos/h2o/h2o/releases/latest | grep tarball | cut -d\" -f4) | tar xz \
        && cd h2o-* \
        && cmake -DWITH_BUNDLED_SSL=on . \
        && make install \
        && cd .. \
        && rm -rf h2o-* \
    && apk del build-base \
               cmake \
               curl \
               linux-headers \
               zlib-dev \
               ca-certificates curl wget \
    && rm -rf /var/cache/apk/*


COPY h2o.conf /etc/

WORKDIR /var/www/html

EXPOSE 8080 8443

RUN addgroup h2o && adduser -G h2o -D -H h2o
USER h2o

CMD ["h2o", "-c", "/etc/h2o.conf"]
