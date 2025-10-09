# Running Bee2 within Docker containers

## Install Docker

We need Docker with support for multi-platform images. This support is provided
by the `buildx` plugin included by default in `docker-desktop` and available 
for `docker-ce` and `moby-engine`.

Install on Ubuntu: 
[https://docs.docker.com/engine/install/ubuntu/](https://docs.docker.com/engine/install/ubuntu/).

## Prepare Docker

First time:

```
docker buildx create --name mybuilder
docker buildx use mybuilder 
```

Next times:
```
docker run --privileged --rm tonistiigi/binfmt:master --install all 
``` 

## Update Docker images

```
docker buildx bake debian 
docker buildx bake fedora
```

## Build and test Bee2 on all available platforms

```
docker buildx bake --progress="plain" bee2d 
docker buildx bake --progress="plain" bee2f
```

## Build and test Bee2 on a specific platform

```
docker buildx build --platform linux/amd64 --progress="plain" -f dockerfiles/bee2d.Dockerfile .
docker buildx build --platform linux/amd64 --progress="plain" -f dockerfiles/bee2f.Dockerfile .
```

## Run a terminal on a specific platform

```
docker run --rm -it -v .:/usr/src --platform linux/s390x btls/fedora:cdev bash
```

## Enable experimental Docker features

The `platform` option may not be available in Docker. In this case you need 
to enable experimental Docker CLI features in one of two ways:

* set the environment variable `DOCKER_CLI_EXPERIMENTAL` to `enabled`:
```
export DOCKER_CLI_EXPERIMENTAL=enabled
```

* add the following line to the config file `$HOME/.docker/config.json`:
```
"experimental" : "enabled"
```