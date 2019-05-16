# About

​	The project will discover the port scanner and block them. The port scanner who try to inspect the common ports of server will be logged with iptables and be added into blacklist. 



# Usage

- ### Create ipset

```bash
apt-get install ipset
ipset create TRUST hash:net hashsize 4096 maxelem 1000000 timeout 0
ipset create THREAT hash:net hashsize 4096 maxelem 1000000 timeout 0
```

​	Add client to trust set

```bash
ipset add TRUST x.x.x.x
```

- ### Add iptables rules

```bash
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -m set --match-set TRUST src -j ACCEPT -m comment --comment 'ACCEPT TRUST LIST'
iptables -A INPUT -p icmp -m length --length 128 -j LOG --log-prefix "TRUST: " -m comment --comment 'MARK TRUST' 
iptables -A INPUT -m set --match-set THREAT src -j DROP -m comment --comment 'DROP THREAT LIST' 
iptables -A INPUT -p tcp -m multiport --dports 21,22,23,53,69,80,110,123,443,1080,3128,3306,3389,6379,8080 -j LOG --log-prefix "THREAT: " -m comment --comment 'MARK THREAT'
```

- ### Redirect log

  iptables log will send to /var/log/syslog by default, redirect them to new file.

```bash
vim /etc/rsyslog.d/10-iptables.conf
```

> :msg,contains,"] TRUST: " /var/log/iptables.log
>
> :msg,contains,"] THREAT: " /var/log/iptables.log
>
> & ~

```bash
/etc/init.d/rsyslog restart
```

- ### Initiate

```bash
pip3 install ipdb
./punisher.py --init
```

- ### Add crontab

```bash
crontab -e
```

> */1 * * * * /path/punisher.py --work



​	refer to help menu for more usage.



# Note

​	If user is blocked by trigger, just send a specific size icmp packet to trust himself. 

##### Windows:

```
ping -l 100 x.x.x.x
```

##### Linux/Mac

```
ping -s 100 x.x.x.x
```

