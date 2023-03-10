# About

[EN](https://github.com/sseaky/AntiScan/blob/master/Readme_EN.md)

本项目是为防止暴露在公网的服务器被扫描而设计。

只要连接了预定的敏感端口，这些源IP就会被iptables记录，并通过cron或incron任务将这些源IP加入黑名单一段时间。

目前在 **Ubuntu/Debian/Centos7** 测试过，效果如下。

![install](img/test.gif)



# **安装**

因为程序默认是将22端口加入了敏感端口，为防止错误封堵正常的连接，所以最好将ssh的端口改到别的高端口。

如果被封堵，可以用魔术Ping的方法自行解封。

root用户可以不需要sudo。

```bash
sudo -E bash -c "bash <(wget -qO - https://github.com/sseaky/AntiScan/raw/master/antiscan_onekey.sh) install"
```

或者

```bash
wget https://github.com/sseaky/AntiScan/raw/master/antiscan_onekey.sh
sudo -E bash antiscan_onekey.sh install
```

安装过程如下，可以作必要调整。

![install](img/install.png)

# 魔术Ping

基于零信任设计的思想，程序定义了一个魔术Ping值，只要用户发送指定长度的icmp包，就可以触发程序将源IP加入白名单，放通所有连接。

默认值为100，部署时建议自行修改。

发送指定长度的ICMP包方法如下：

##### Windows:

```
ping -l 100 x.x.x.x
```

##### Linux/Mac

```
ping -s 100 x.x.x.x
```

由于20字节的IP头部和8字节的ICMP头部，所以在iptable规则中，筛选的长度会大于指定长度28字节，

# 使用

```bash
$ antiscan_dog.sh -h

Usage:
  -d    Debug mode
  -r    Run
  -s    Show statistic
  -t    Show statistic with location, need python >= 3.5
  -f    Log file. default /var/log/antiscan.log
  -w    Parse whole log file
  -x    Remove trust ip
  -y    Remove threat ip

Tips:
  Show statistic
    sudo antiscan_dog.sh -s

  Comment/uncomment the item in root's incrontab to disable/enable the trigger:
    sudo incrontab -e

  Alter iptables to customize sensible ports
    sudo iptables -nvL --line-number

  Alter ipset to customize trust/threat list
    sudo ipset list

```

![install](img/show.png)

如果python3可用，可以使用-t参数显示来源，IP数据是基于离线数据。

![install](img/show_loc.png)

# 更新

```bash
sudo -E bash -c "bash <(wget -qO - https://github.com/sseaky/AntiScan/raw/master/antiscan_onekey.sh) update"
```



# 问题

### tail: inotify resources exhausted

Append to /etc/sysctl.conf

```
fs.inotify.max_user_watches = 1048576
fs.inotify.max_user_instances = 1048576
```

\# sysctl -p



# 2023.3.10

增加FORWARD链的封堵。对于容器映射到主机流量，INPUT链无效



# 2022.1.29

添加了antissh.sh功能，防止对ssh的爆破

先安装jq

```
apt install jq
```

多次尝试ssh失败的IP，会被记录于 /etc/hosts.deny

```
ALL:206.189.xx.xx:deny # Sun Jan 30 22:14:10 CST 2022 | United Kingdom.England.London
```





增加选择crontab和incrontab

 incrontab，即时生效，但威胁日志较多时，比较消耗资源

```
/var/log/btmp   IN_MODIFY     flock -xn /root/.antissh.lock bash /usr/bin/antissh.sh
```

crontabe，周期检查，会有一定的空档期

```
*/5 * * * * /usr/bin/antissh.sh
```





