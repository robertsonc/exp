# exp lab client: an attendee device. DHCP on its VLAN, background traffic (scripts/traffic.sh), and real speed tests
# through the exp page in headless Chromium (speedtest-run.js), so results flow through the whole pipeline.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      ca-certificates curl iperf3 dnsutils iproute2 iputils-ping isc-dhcp-client procps nodejs npm \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/lab
# same Playwright pin as CI (.github/workflows/ci.yml browser job)
RUN npm install --no-audit --no-fund playwright@1.63.0 \
 && npx --no-install playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/* /root/.npm
COPY speedtest-run.js traffic-loop.sh /opt/lab/
RUN chmod 0755 /opt/lab/traffic-loop.sh
CMD ["sleep", "infinity"]
