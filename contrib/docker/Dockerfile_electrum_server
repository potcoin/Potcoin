###############################################################
# Dockerfile to build potcoin-electrum server container images
# Based on Ubuntu
###############################################################

FROM ubuntu:14.04
MAINTAINER laudney

RUN apt-get update
RUN apt-get install -y git make g++ python-setuptools python-openssl python-leveldb python-dev libleveldb-dev wget
RUN apt-get clean
RUN easy_install jsonrpclib irc plyvel

RUN adduser potcoin --disabled-password
USER potcoin

WORKDIR /home/potcoin
RUN mkdir bin src
RUN echo PATH=\"\$HOME/bin:\$PATH\" >> .bash_profile

WORKDIR /home/potcoin/src
RUN git clone https://github.com/potcoin-project/potcoin-electrum-server.git

USER root
WORKDIR /home/potcoin/src/potcoin-electrum-server
RUN ./configure
RUN python setup.py install

WORKDIR /var
RUN touch /var/log/electrum.log
RUN chown potcoin:potcoin /var/log/electrum.log
RUN wget -q http://reddwallet.org/electrum.tar.gz
RUN tar -zxvf electrum.tar.gz
RUN rm electrum.tar.gz
RUN chown potcoin:potcoin -R electrum-server

RUN echo "potcoin hard nofile 65536" >> /etc/security/limits.conf
RUN echo "potcoin soft nofile 65536" >> /etc/security/limits.conf

USER potcoin
WORKDIR	/home/potcoin
RUN openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
RUN openssl rsa -passin pass:x -in server.pass.key -out server.key
RUN rm server.pass.key
RUN openssl req -new -key server.key -out server.csr -subj '/CN=www.my.com/O=My Company Name LTD./C=US'
RUN openssl x509 -req -days 730 -in server.csr -signkey server.key -out server.crt

ENV HOME /root
EXPOSE 50001 50002
USER root
