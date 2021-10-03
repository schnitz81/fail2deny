# fail2deny
An alternative to fail2ban that only uses one script file instead of modules and bans in the tcp wrapper instead of iptables.
Automatic banning of IPv4 addresses after too many failed login attempts.

## TCP wrapper or iptables
Two versions are included. One utilizing TCP wrappers and one using iptables.

### TCP wrapper:
- Accessing /etc/hosts.deny for banning.
- Permanent bans only.
- Docker build available for running as container.

### iptables:
- Accessing iptables directly.
- Creating and using /etc/fail2deny.list for internal use.
- Temporary bans (ban time can be set in the .sh file).
- No Docker version, because there is no standard solution for accessing iptables in the host and such practice is not recommended.

## Requirements
This script utilizes the inotify functionality. The inotify tools package needs to be installed. Depending on version used, a TCP wrapper utility or iptables needs to be installed as well.

## Usage
Input up to five log files as arguments.
Example:<br>
```./fail2deny.sh /var/log/auth.log /var/log/vsftpd.log```

### Running in Docker
Build example:<br>
```docker build . -t fail2deny```

You need to mount your hosts.deny file and log folder when running. The log files to be monitored need to be passed as arguments Just like when the script is running individually.
Run example:<br>
```docker run -d --rm --name fail2deny -v /etc/hosts.deny:/etc/hosts.deny -v /var/log:/var/log:ro fail2deny /var/log/auth.log``` 

To see the events of the detached container in realtime:<br>
```docker logs -f (CONTAINER ID)```

## License

MIT License

Copyright (c) 2017

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
