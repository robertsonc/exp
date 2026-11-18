# A systemd host for the exp-agent acceptance tests (agent/tests/container/). The agent and install.sh
# run in it exactly as on a VM: systemd is PID 1, apt/curl/openssl/python3 are the distro's.
# Build: docker build --build-arg UBUNTU=24.04 -t exp-agent-systemd:24.04 agent/tests/container
# Run with --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock.
ARG UBUNTU=24.04
FROM ubuntu:${UBUNTU}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus python3 curl openssl iproute2 \
      ca-certificates sudo procps iputils-ping >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask getty@tty1.service systemd-logind.service systemd-resolved.service >/dev/null 2>&1 || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
