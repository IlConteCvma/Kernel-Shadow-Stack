# To build the dev environment.
# docker build -t elfloader_builder .

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get dist-upgrade -y && \
	    apt-get -y install curl build-essential git autoconf automake libtool bison flex gcc ruby rake bundler git mingw-w64 && \
		apt-get clean && \
		rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

