# exp lab client: an attendee device. DHCP on its VLAN, background traffic (scripts/traffic.sh), and real speed tests
# through the exp page in headless Chromium (speedtest-run.js), so results flow through the whole pipeline.
# Base: Playwright's own image for the CI pin (ci.yml PLAYWRIGHT_VERSION 1.63.0): Ubuntu 24.04 with a Node that
# Playwright supports (Ubuntu's own nodejs is 18; Playwright 1.63 needs >= 20) and Chromium already installed.
FROM mcr.microsoft.com/playwright:v1.63.0-noble
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      ca-certificates curl iperf3 dnsutils iproute2 iputils-ping isc-dhcp-client procps \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/lab
# the library only: the browsers are already in the base image (PLAYWRIGHT_BROWSERS_PATH=/ms-playwright)
RUN npm install --no-audit --no-fund --ignore-scripts playwright@1.63.0 && rm -rf /root/.npm
COPY speedtest-run.js traffic-loop.sh /opt/lab/
RUN chmod 0755 /opt/lab/traffic-loop.sh
CMD ["sleep", "infinity"]
