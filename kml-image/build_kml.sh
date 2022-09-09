#!/bin/bash
docker build -t kml .
docker container create --name buildkml kml
docker cp buildkml:/home/kml/linux-firmware-image-4.0.0-kml_4.0.0-kml-6_amd64.deb ./
docker cp buildkml:/home/kml/linux-headers-4.0.0-kml_4.0.0-kml-6_amd64.deb ./
docker cp buildkml:/home/kml/linux-image-4.0.0-kml-dbg_4.0.0-kml-6_amd64.deb ./
docker cp buildkml:/home/kml/linux-image-4.0.0-kml_4.0.0-kml-6_amd64.deb ./
docker cp buildkml:/home/kml/linux-libc-dev_4.0.0-kml-6_amd64.deb ./
docker cp buildkml:/home/kml/linux-4.0/arch/x86/boot/bzImage ./
docker container rm -f buildkml

