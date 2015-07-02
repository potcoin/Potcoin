############################################################
# Dockerfile to build potcoind container images
# Based on Ubuntu
############################################################

FROM ubuntu:14.04
MAINTAINER laudney

RUN apt-get update
RUN apt-get install -y git make g++ python-leveldb libboost-all-dev libssl-dev libdb++-dev pkg-config libminiupnpc-dev wget xz-utils
RUN apt-get clean

RUN adduser potcoin --disabled-password
USER potcoin

WORKDIR /home/potcoin
RUN mkdir bin src
RUN echo PATH=\"\$HOME/bin:\$PATH\" >> .bash_profile

WORKDIR /home/potcoin/src
RUN git clone https://github.com/potcoin-project/potcoin.git

WORKDIR	/home/potcoin/src/potcoin/src
RUN make -f makefile.unix
RUN strip potcoind
RUN cp -f potcoind /home/potcoin/bin/
RUN make -f makefile.unix clean

WORKDIR	 /home/potcoin
RUN mkdir .potcoin
RUN cp -f src/potcoin/contrib/docker/potcoin.conf .potcoin/

WORKDIR /home/potcoin/.potcoin
RUN wget -q https://github.com/potcoin-project/potcoin/releases/download/v1.3.1.2/bootstrap.dat.xz

ENV HOME /home/potcoin
EXPOSE 8332
USER potcoin
