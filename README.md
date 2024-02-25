# fail2deny
An alternative to fail2ban that only uses one script file instead of modules and bans abusive IPv4 adresses with iptables or nftables.
Automatic temporary ban of IPv4 addresses after too many failed login attempts.

## nftables or iptables
iptables is prioritized when available in order to not collide with the iptables-nft tool.

## function:
- Accessing iptables/nft directly.
- Creating and using /etc/fail2deny.list for internal use.
- Selectable ban time. Can be set in the .sh file.
- File logging of bans and unbans. This event log location can be set in the .sh file.

## Requirements
This script utilizes the inotify functionality. The inotify tools package needs to be installed. Depending on version used, a TCP wrapper utility or iptables needs to be installed as well.

## Usage
Input up to five log files as arguments.
Example:<br>
```./fail2deny.sh /var/log/auth.log /var/log/vsftpd.log```


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
