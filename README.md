# myTcpIp
1. 向虚拟机网卡发送数据
抓包\1\直接往网卡扔数据.pcapng, 因为没有任何协议的包装, 所以只会显示物理层,数据链层和发的数据

2. 将虚拟机发过来的ping命令的数据,修改前两个字节,然后直接扔回网卡
抓包\2\将虚拟机ping的数据修改发回.pcapng  附有分析文档

3. 新增两个简单的echo程序, 分别作为client和server与socketTool工具进行简单的交互

4. arp协议:发送arp数据包

5. 无回报arp

6. 回复arp包

7. 当需要发送IP包时,首先从ARP缓存中找表项,如果找到则使用其中的值进行更新;
	如果没有则发送查询请求,并将包加入到等待队列中.等下一次收到请求时,再将
	数据包发送出去

8. 给缓存表项增加超时重新请求
9. 由于网络中的计算机可能因为各种原因退出,所以IPV4地址可能分配给不同的计算机
	ARP缓存表必须设置有效期,以便保持较新的状态

10. ICMPV4包的处理

11. 响应ping请求