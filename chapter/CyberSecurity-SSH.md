# Cyber-Security:OpenSSH并不绝对安全

## 摘要
OpenSSH7.0做出了一些变更，默认禁用了一些较低版本的密钥算法。受此影响，在同一系统中的主机、网络设备必须同步升级，或者开启兼容选项。 实测中，也有某些厂家产品内核的原因，甚至无法升级。由此案例，关于系统版本管理、安全、架构、开源文档，甚至采购方面，都可以引发很多思考。

### 背景
某系统按照安全管理要求，需对全系统主机的OpenSSH版本升级。
第一次测试：系统自有服务器。主机：RedHat Linux ／SunOS：系统内全部主机升级，内部互通没有问题
第二次测试：主机到网络设备SSH互通性

#### 国外厂商
思科（系统版本IOS 12.0系列，IOS 4.0系列），RedBack（系统版本SEOS-12系列，SEOS-6.0系列）。
目前仅支持diffie-hellman-group1-sha1、ssh-dss两种算法。
当然不排除今年国产化运动影响，国外厂商维保过期等原因导致的售后升级服务滞后。
#### 国内厂商
华为，无论是城域骨干网设备，还是IPRAN 各型号，甚至老式交换机都完全兼容。
中兴，只有较新的CTN9000-E V3.00.10系列能有限支持diffie-hellman-group1-sha1，
其它各型号在服务器OpenSSH7.0以上版本后都无法正常访问。

### 原因解析

#### 直接原因：OpenSSH7.0安全特性升级
基于安全考虑，OpenSSH7.0将diffie-hellman-group1-sha1，ssh-dss等运行时状态默认变更为禁用。
Support for the 1024-bit diffie-hellman-group1-sha1 key exchange is disabled by default at run-time.
Support for ssh-dss, ssh-dss-cert-* host and user keys is disabled by default at run-time*

#### 采购原因：国产化运动
国产化是近年以来的国家战略，各行各业都有涉及。在本次案例中，国际大厂Cicso,RedBack,Juniper等，个人以为更大的可能不是无法更新，而是基于商务原因。既然你不在维保合同期之内，又没有继续采购的计划，那我干嘛还给你升级？
甚至由此可以推论：针对在网国外厂商设备，漏洞多又没有升级保障，会变成攻击和防护的重灾区。

#### 软件质量：厂商系统架构水平差异
同样是国内厂家，测试对比结果却非常强烈！！这其实是没有想到的。通过这个小细节，可以看出华为的系统架构与中兴早已拉开境界上的差距。结合近年来，华为出入开源社区的身影，更可以说明其对系统内核的理解和掌握已经到了相当的程度。
个人揣测，其早期版本可能也没有多好的支持。由于架构设计较好，又有更高的自我要求，逐步通过补丁升级，不动声色地就更新好了。持续升级能力，可以作为评价企业长期

### OpenSSH7.0以后的演进
针对密钥强度和加密算法方面更新会持续加强，必须有所准备
We plan on retiring more legacy cryptography in the next releaseincluding:
* Refusing all RSA keys smaller than 1024 bits (the current minimumis 768 bits)
* Several ciphers will be disabled by default: blowfish-cbc,cast128-cbc, all arcfour variants and the rijndael-cbc aliasesfor AES.
* MD5-based HMAC algorithms will be disabled by default.

#### 延伸：Logjam Attack
（本人没查到对应的中文名称，暂翻译为“僵尸攻击”，欢迎指正）
一种针对Diffie-Hellman密钥交换技术发起的攻击，而这项技术应用于诸多流行的加密协议，比如HTTPS、TLS、SMTPS、SSH及其他协议。一个国外计算机科学家团队2015-5-20公开发布。


#### 延伸：开源组件演进追踪
本案例实际操作过程中，开头走了很多弯路，并没有一下找到要害。
根源在于团队缺乏关注开源产品演进方向的意识和习惯，也缺乏直接阅读、理解官方文档的习惯。

### OpenSSH 7.0 变更说明
Changes since OpenSSH 6.9
=========================
This focus of this release is primarily to deprecate weak, legacyand/or unsafe cryptography.
Security--------

* sshd(8): OpenSSH 6.8 and 6.9 incorrectly set TTYs to be world-
writable. Local attackers may be able to write arbitrary messages
to logged-in users, including terminal escape sequences.
Reported by Nikolay Edigaryev.

* sshd(8): Portable OpenSSH only: Fixed a privilege separation
weakness related to PAM support. Attackers who could successfully
compromise the pre-authentication process for remote code
execution and who had valid credentials on the host could
impersonate other users.  Reported by Moritz Jodeit.

* sshd(8): Portable OpenSSH only: Fixed a use-after-free bug
related to PAM support that was reachable by attackers who could
compromise the pre-authentication process for remote code
execution. Also reported by Moritz Jodeit.

* sshd(8): fix circumvention of MaxAuthTries using keyboard-
interactive authentication. By specifying a long, repeating
keyboard-interactive "devices" string, an attacker could request
the same authentication method be tried thousands of times in
a single pass. The LoginGraceTime timeout in sshd(8) and any
authentication failure delays implemented by the authentication
mechanism itself were still applied.

Found by Kingcope.
Potentially-incompatible Changes
--------------------------------
* Support for the legacy SSH version 1 protocol is disabled by
default at compile time.
* Support for the 1024-bit diffie-hellman-group1-sha1 key exchange
is disabled by default at run-time. It may be re-enabled using
the instructions athttp://www.openssh.com/legacy.html
* Support for ssh-dss, ssh-dss-cert-* host and user keys is disabled
by default at run-time. These may be re-enabled using the
instructions at http://www.openssh.com/legacy.html
* Support for the legacy v00 cert format has been removed.
* The default for the sshd_config(5) PermitRootLogin option has changed from "yes" to "prohibit-password".
* PermitRootLogin=without-password/prohibit-password now bans all
interactive authentication methods, allowing only public-key,hostbased and GSSAPI authentication (previously it permitted keyboard-interactive and password-less authentication if those were enabled).

#### 解决方案（翻译）
OpenSSH实现了所有符合SSH标准的加密算法，使得应用之间可以互相兼容，但是自从一些老式的算法被发现不够强壮以来，并不是所有的算法都会默认启用。
当OpenSSH拒绝连接一个只支持老式算法的应用时，我们该如何做呢？
当一个SSH客户端与一个服务端建立连接的时候，两边会互相交换连接参数清单。清单包括用于加密连接的编码信息，消息认证码（MAC）用于防止网络嗅探篡改，
公钥算法可以让服务端向客户端证明它是李刚（我就是我，而不是另一个“我”），密钥交换算法是用来生成每次连接的密钥。在一次成功的连接中，这里的每个参数必须有一组互相支持的选择。
当客户端和服务端通讯的时候，不能匹配到一组互相支持的参数配置，那么这个连接将会失败。
OpenSSH(7.0及以上版本）将输出一个类似的错误信息：
~~~
Unable to negotiate with 127.0.0.1: no matching key exchange method found.
Their offer: diffie-hellman-group1-sha1
~~~
在这种情况下，客户端和服务端不能够就密钥交换算法达成一致。服务端只提供了一个单一的算法 ：diffie-hellman-group1-sha1。
OpenSSH可以支持这种算法，但是它默认不启用，因为这个算法非常弱，理论上存在僵尸攻击的风险。
这个问题的最好的解决方案是升级软件。
OpenSSH禁用的算法，都是那些我们明确不推荐使用的，因为众所周知它们是不安全的。
在某些情况下，立科升级也许是不可能的，你可能需要临时地重新启用这个较弱的算法以保持访问。
在上面这种错误信息的情况下，OpenSSH可以配置启用diffie-hellman-group1-sha1 密钥交换算法（或者任何其它被默认禁用的），
可通过KexAlgorithm选项－或者在命令行：
~~~
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 user@127.0.0.1
~~~
或者在 ~/.ssh/config 配置文件中:
~~~
Host somehost.example.org
KexAlgorithms +diffie-hellman-group1-sha1
~~~

命令行中ssh和“＋”号之间连接算法选项的配置，对客户端默认设置来说相当于替换。通过附加信息，你可以自动升级到最佳支持算法，当服务端开始支持它的时候。另一个例子，主机验证过程中，当客户端和服务端未能就公钥算法达成一致的时候：

~~~
Unable to negotiate with 127.0.0.1: no matching host key type found.
Their offer: ssh-dss
~~~
OpenSSH 7.0及以上版本同样禁用了ssh-css(DSA)公钥交换算法。
它也太弱了，我们强烈不建议使用它。
~~~
ssh -oHostKeyAlgorithms=+ssh-dss user@127.0.0.1
~~~
或者在 ~/.ssh/config 配置文件中:
~~~
Host somehost.example.org
HostkeyAlgorithms ssh-dss
~~~
视服务端配置情况而定，验证过程中其它连接参数也可能失败。
你启用它们的时候，也许需要确定编码方式或者消息验证码配置选项。
延伸：查询 SSH 已支持的算法
~~~
ssh -Q cipher       # 支持的编码方式
ssh -Q mac          # 支持的消息验证码
ssh -Q key          # 支持的公钥类型
ssh -Q kex          # 支持的密钥交换算法
~~~
最后，当你需要试图连接一个特殊主机的时候，也可以通过－G选项查询实际使用ssh配置。
~~~
ssh -G  user@somehost.example.com
~~~
将列出所有的配置选项，包括被选用的编码方式，消息验证码，公钥算法，密钥算法参数的值。

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
- [赵亚：令人作呕的OpenSSL](http://blog.csdn.net/dog250/article/details/24552307)
