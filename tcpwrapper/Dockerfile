FROM alpine:3.12

LABEL maintainer="schnitz"
LABEL description="Lightweight fail2ban alternative with TCP wrapper ban instead of firewall ban."
LABEL url="https://github.com/schnitz81/fail2deny"

RUN apk --no-cache update
RUN apk --no-cache add coreutils bash inotify-tools
COPY fail2deny.sh /
RUN chmod +x /fail2deny.sh
ENTRYPOINT ["/fail2deny.sh"]

# Build:
# $ docker build . -t fail2deny

# Run:
# $ docker run -d --restart unless-stopped --name fail2deny -v /etc/hosts.deny:/etc/hosts.deny -v /var/log:/var/log:ro schnitz81/fail2deny /var/log/auth.log

# (Add more log file paths to the run command for additional monitoring)
