FROM --platform=$TARGETPLATFORM debian:stable

RUN apt-get update && apt-get install -y cmake git gcc doxygen clang

WORKDIR /usr/src