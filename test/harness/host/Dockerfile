# An exp "host": ubuntu with systemd as PID 1, the packages the components' requirements.apt name
# pre-installed (so the installer's apt step is a no-op and tests need no network), python3/openssl for
# the manual installer. Run --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run.
ARG UBUNTU=24.04
FROM ubuntu:${UBUNTU}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus python3 openssl ca-certificates \
      iproute2 iputils-ping busybox curl iperf3 iw wpasupplicant procps sqlite3 dnsutils iptables >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask getty@tty1.service systemd-logind.service systemd-resolved.service >/dev/null 2>&1 || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
