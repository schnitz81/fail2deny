# fail2deny
An alternative to fail2ban that only uses one script file instead of modules and bans in the tcp wrapper instead of iptables.

## Requirements
This script utilizes the inotify functionality. The inotify-tools tools package needs to be installed.

## Usage
Input up to five log files as arguments.
Example:
```./fail2deny.sh /var/log/auth.log /var/log/vsftpd.log```

### Running in Docker
Build example:
```docker build . -t fail2deny```

You need to mount your hosts.deny file and log folder when running. The log files to be monitored need to be passed as arguments Just like when the script is running individually.
Run example:
```docker run -v /etc/hosts.deny:/etc/hosts.deny -v /var/log:/var/log:ro fail2deny /var/log/auth.log``` 

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
