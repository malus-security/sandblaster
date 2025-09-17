FROM debian:bullseye

RUN set -xe; \
    apt-get -yqq update; \
    apt-get install -y libstdc++6 python2.7 python3 python3-pip; \
	pip3 install lief;

COPY  helpers /sandblaster/helpers/
COPY reverse-sandbox /sandblaster/reverse-sandbox
COPY sb_parser /sandblaster/sb_parser

WORKDIR /sandblaster/sb_parser

# apparently if you remove the 'make clean' line it goes bang :)
RUN make clean
RUN make
