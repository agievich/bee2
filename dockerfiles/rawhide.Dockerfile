FROM --platform=$TARGETPLATFORM fedora:rawhide

RUN dnf -y update

RUN dnf install -y gcc clang cmake doxygen

WORKDIR /usr/src
