# The simulated event LAN ("net" container): bridge, gateway -> edge -> isp router chain as namespaces,
# dnsmasq (DHCP + DNS), local HTTP(S) targets, fault API. Run --privileged --pid=host (see harness.sh).
# The scripts are bind-mounted at /opt/lan, so editing them needs no rebuild.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends iproute2 iptables dnsmasq-base python3 openssl \
      iputils-ping curl procps tcpdump ca-certificates util-linux >/dev/null \
 && rm -rf /var/lib/apt/lists/*
CMD ["/opt/lan/lan-up.sh"]
