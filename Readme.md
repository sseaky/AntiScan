# About

The project will deploy a mechanism on server to anti port scanner.

The port scanner who try to inspect the sensitive ports of server will be logged with iptables and be added into blacklist by incron task immediately for certain time.

Test on **Ubuntu/Debian**.

# **Install**

```bash
sudo -E bash -c "bash <(wget -qO - https://github.com/sseaky/AntiScan/raw/master/antiscan_onekey.sh) install"
```

or

```bash
wget https://github.com/sseaky/AntiScan/raw/master/antiscan_onekey.sh
sudo -E bash antiscan_onekey.sh install
```

![install](img/install.png)

# Magic Ping

There is a magic length to set up on installment, If user want to add current server to trust list, just send the a icmp packet of magic length (default 100).

##### Windows:

```
ping -l 100 x.x.x.x
```

##### Linux/Mac

```
ping -s 100 x.x.x.x
```

# Usage

```bash
$ antiscan_dog.sh -h

Usage:
  -d    Debug mode
  -r    Run
  -s    Show statistic
  -f    Log file. default /var/log/antiscan.log
  -x    remove trust ip
  -y    remove threat ip

Tips:
  Comment/uncomment the item in root's incrontab to disable/enable the trigger:
    sudo incrontab -e

  Alter iptables to customize sensible ports
    sudo iptables -nvL --line-number

  Alter ipset to customize trust/threat list
    sudo ipset list

```

