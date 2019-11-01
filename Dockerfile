FROM alpine
RUN apk update
RUN apk add coreutils bash inotify-tools
COPY fail2deny.sh /
RUN chmod +x /fail2deny.sh
ENTRYPOINT ["/fail2deny.sh"]

# Build:
# $ docker build . -t fail2deny

# Run:
# $ docker run -d --rm --name fail2deny -v /etc/hosts.deny:/etc/hosts.deny -v /var/log:/var/log:ro fail2deny /var/log/auth.log 

# (Add more log file paths to the run command for additional monitoring)
