# exp lab host: a systemd "VM" for the exp components (collector, runner, dashboard, speedtest, probes) and for the
# lab's support nodes (svc: Kea DHCP + dnsmasq DNS + rsyslog; isp: NAT). install.sh runs in it as on a real
# Ubuntu 24.04 host. Base: the systemd image already on the lab VM. Pin it by digest once pulled:
#   docker inspect --format '{{index .RepoDigests 0}}' jrei/systemd-ubuntu:24.04
FROM jrei/systemd-ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      python3 curl openssl ca-certificates iproute2 iputils-ping busybox iperf3 tcpdump procps sudo \
      dnsmasq kea-dhcp4-server rsyslog iptables isc-dhcp-client dnsutils \
 && rm -rf /var/lib/apt/lists/*
# dnsmasq and Kea only run on svc (the topology enables them there); elsewhere dnsmasq would take :53 from the
# speedtest DNS leg. getty/logind/resolved have no job in a container and resolved would also want :53.
RUN systemctl disable dnsmasq kea-dhcp4-server iperf3 \
 && systemctl mask getty@tty1.service systemd-logind.service systemd-resolved.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
