# Tiny image for the probe's real-namespace tests (run privileged: it creates veths and namespaces).
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 busybox python3 python3-pytest python3-dnspython dnsmasq-base curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /exp
