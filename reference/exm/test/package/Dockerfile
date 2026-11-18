# A systemd host for test/package.sh: the release tarballs are installed into containers built from this,
# so the installers, units and services run exactly as on a VM. Run with --privileged and /sbin/init.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus openssh-server openssh-client \
    python3 python3-scapy python3-dnspython curl iproute2 busybox-static dnsmasq-base iptables tcpdump procps ca-certificates \
    iputils-ping openssl sudo nodejs tzdata >/dev/null && rm -rf /var/lib/apt/lists/* \
 && systemctl mask getty@tty1.service systemd-logind.service >/dev/null 2>&1 || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
