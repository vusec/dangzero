FROM ubuntu:14.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update
RUN apt install -y build-essential libncurses-dev bison flex libelf-dev libssl-dev bc wget
RUN mkdir -p /home/kml
WORKDIR /home/kml
RUN wget -O kernel.gz download.vusec.net/dataset/kml-kernel.tar.gz
RUN tar -xf kernel.gz
WORKDIR /home/kml/linux-4.0
RUN make -j`nproc` deb-pkg
