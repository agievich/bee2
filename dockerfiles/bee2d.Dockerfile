FROM --platform=$TARGETPLATFORM btls/debian:cdev

COPY . /usr/src

RUN gcc --version
RUN clang --version
RUN cat /etc/os-release

WORKDIR /usr/src
RUN rm -rf ./build_gcc; mkdir build_gcc
RUN rm -rf ./build_clang; mkdir build_clang

WORKDIR /usr/src/build_gcc
RUN CC=gcc cmake ..
RUN make
RUN ctest --verbose

WORKDIR /usr/src/build_clang
RUN CC=clang cmake ..
RUN make
RUN ctest --verbose

WORKDIR /usr/src