# Cyber Academy Reverse Engineering Course Dockerfile
# Run these commands to get started:
#   docker-compose build
#   docker-compose up -d
#   docker exec -it unicorn_scripts /bin/bash

FROM ubuntu:bionic

ENV DEBIAN_FRONTEND noninteractive

# == Do the basics =========================================
RUN apt-get update
RUN apt-get -y install apt-utils git vim
RUN apt-get -y install python python-pip

# == Install Unicorn ============================================
RUN pip install unicorn

# == Troubleshooting ===========================================
# If you get an error about no candidate for `apt-utils` you
# likely have an old docker-ce version. Update with this:
# curl -fsSL get.docker.com | sh

