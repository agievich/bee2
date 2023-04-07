# Install Docker
We need Docker with multi-platform image support. Plugin `buildx` is included by default to `docker-desktop`, and available for `docker-ce` and `moby-engine`.

Debian: 
```
apt install moby-engine moby-buildx moby-compose moby-cli
```
Ubuntu:
https://docs.docker.com/engine/install/ubuntu/

# Prepare Docker to work with multi-platform images
First time:
```
docker buildx create --name mybuilder
docker buildx use mybuilder 
```
Each time:
```
docker run --privileged --rm tonistiigi/binfmt --install all 
``` 

# Update images for build
```
docker buildx bake debian 
docker buildx bake fedora
```

# Run build and test on the all available platforms
```
docker buildx bake --progress="plain" bee2d 
docker buildx bake --progress="plain" bee2f
```

# Run build and test on a one of available platforms
```
docker buildx build --platform linux/amd64 --progress="plain" -f dockerfiles/bee2d.Dockerfile .
docker buildx build --platform linux/amd64 --progress="plain" -f dockerfiles/bee2f.Dockerfile .
```

# Run terminal on specified platform image
```
docker run --rm -it -v .:/usr/src --platform linux/s390x btls/fedora:cdev bash
```

### Turn on experimental features
If option `platform` is unavailable in Docker, you need turn on experimental Docker CLI features in one of two ways. Either by setting an environment variable
```
$ export DOCKER_CLI_EXPERIMENTAL=enabled
```
or by turning the feature on in the config file $HOME/.docker/config.json:
```
{
  …
  "experimental" : "enabled"
}
```