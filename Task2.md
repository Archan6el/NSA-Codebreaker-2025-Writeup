## Task 2 - The Hunt Continues - (Network Forensics)

> With your help, the team concludes that there was clearly a sophisticated piece of malware installed on that endpoint that was generating some network traffic. Fortunately, DAFIN-SOC also has an IDS which retained the recent network traffic in this segment.

> DAFIN-SOC has provided a PCAP to analyze. Thoroughly evaluate the PCAP to identify potential malicious activity.

> Downloads: PCAP to analyze (traffic.pcap)

> Prompt: Submit all the IP addresses that are assigned to the malicious device, one per line

### Solve:

Oh boy I know this one messed with a lot of people, and it got me too, until I found the needle in the haystack

Since the prompt asks us to find "all the IP addresses that are assigned to the malicious device, one per line", I immediately assumed that the answer would be found by finding a MAC address that is using multiple IPs

Using tshark, I ran a command to print sender MAC Addresses and the IP's used

```bash
tshark -r traffic.pcap \
  -T fields \
  -e sll.src.eth \
  -e ip.src \
  -E separator=$'\t' |
awk '
{
  mac=$1
  ip=$2

  if (mac != "" && !(mac in seen_mac)) {
    print mac
    seen_mac[mac]=1
  }

  if (mac != "" && ip != "") {
    key = mac FS ip
    if (!(key in seen)) {
      printf "%s\t%s\n", mac, ip
      seen[key]=1
    }
  }

  if (mac == "" && ip != "") {
    lone[ip]=1
  }
}
END {
  for (ip in lone) {
    printf "\t%s\n", ip
  }
}'
```

Then used a Python script to read through the output and give me a clean result:

```python
from collections import defaultdict

mac_to_ips = defaultdict(set)

with open("mac_ip_pairs.txt") as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) == 2:
            mac, ips_str = parts
            # Split by comma in case there are multiple IPs
            for ip in ips_str.split(','):
                ip_clean = ip.strip()
                if ip_clean:
                    mac_to_ips[mac].add(ip_clean)

for mac in sorted(mac_to_ips):
    print(f"{mac}: {', '.join(sorted(mac_to_ips[mac]))}")
```

We get an interesting result when running this script

```
00:0c:29:17:09:04: 172.21.1.5, 192.168.1.140, 192.168.2.254, 192.168.2.50, 192.168.4.1, 192.168.5.1
00:0c:29:17:09:0e: 0.0.0.0, 172.21.1.254, 192.168.2.254, 192.168.2.50
00:0c:29:17:09:18: 192.168.2.50
00:0c:29:17:09:22: 192.168.2.50
00:0c:29:17:09:2c: 192.168.2.50, 192.168.46.133, 192.168.46.2
00:0c:29:40:71:dc: 192.168.2.50
00:0c:29:42:d9:fe: 172.21.1.5, 192.168.2.50
00:0c:29:6b:81:d4: 172.21.1.230
00:0c:29:77:42:f6: 192.168.3.254, 192.168.5.1
00:0c:29:d6:0d:49: 192.168.1.140, 192.168.1.254, 192.168.2.50, 192.168.4.1
00:50:56:ea:6e:7a: 192.168.46.2, 216.31.17.12, 45.83.234.123
00:50:56:f4:78:30: 192.168.46.254
```

Looks like there are multiple MAC Addresses that are sending packets using different IP addresses. Well, this got a whole lot more complicated. 

I tried submitting some of these to see if any of these were correct, and interestingly, submitting the two IPs assigned to the MAC `00:0c:29:77:42:f6` as seen here:

`00:0c:29:77:42:f6: 192.168.3.254, 192.168.5.1`

Actually gave me a different "Incorrect answer" message stating that I had some of the correct IPs but not all of them. Where to go from here?

Skipping the hours of going through the pcap in Wireshark trying to find anything interesting, I finally found the aforementioned needle in the haystack. 

![image1](./images/task2img1.png)

When filtering by FTP traffic, we can see some files get transmitted. In the above image is one such example where we see a file `router3_backup.config` being transmitted. There are actually 2 more of these router config files transmitted as well, `router1_backup.config` and `router2_backup.config`, but this 3rd one is the most interesting. 

If we look at its contents we can see some interesting things:

```
config interface 'loopback'
    option device 'lo'
    option proto 'static'
    option ipaddr '127.9.7.3'
    option netmask '255.0.0.0'

config globals 'globals'
    option ula_prefix 'fdf2:87c7:eb73::/48'
    option packet_steering '1'

config device
    option name 'br-lan'
    option type 'bridge'
    list ports 'eth0'

config interface 'lan'
    option device 'br-lan'
    option proto 'static'
    option ipaddr '192.168.3.254'
    option netmask '255.255.255.0'
    option ip6assign '60'

config interface 'to_openwrt2'
    option device 'eth1'
    option proto 'static'
    list ipaddr '192.168.5.1/28'

config interface 'host_nat'
    option proto 'dhcp'
    option device 'eth2'

config route
    option target '192.168.3.0/24'
    option gateway '192.168.3.254'
    option interface 'lan'

config route
    option target '0.0.0.0/0'
    option gateway '192.168.5.2'
    option interface 'to_openwrt2'
```

Well would you look at that, the two IPs we know are correct are being used as the `ipaddr` for the `config interface` settings!

```
config interface 'lan'
    option device 'br-lan'
    option proto 'static'
    option ipaddr '192.168.3.254'          <--- Here
    option netmask '255.255.255.0'
    option ip6assign '60'

config interface 'to_openwrt2'
    option device 'eth1'
    option proto 'static'
    list ipaddr '192.168.5.1/28'          <--- Here
```

So this configuration file is definitely heading in the right direction. What are the missing IPs though? Well the prompt does ask for "*all* the IP addresses that are assigned to the malicious device", which means that that would include the IP used in the loopback interface:

```
config interface 'loopback'
    option device 'lo'
    option proto 'static'
    option ipaddr '127.9.7.3'
    option netmask '255.0.0.0'
```

So `127.9.3.7` was our last IP we were missing

Submitting

```
192.168.3.254
192.168.5.1
127.9.7.3
```

solves this task!


As a sidenote, after looking back at this task for this writeup, it appears that I got the right answer but I didn't really follow the intended solve

So the malicous device is actually a malicious DNS server. By filtering for DNS, and working backwards since we know its assigned IPs now, specifically using `192.168.3.254`, we can see that it was providing malicious DNS responses to queries for `archive.ubuntu.com`

![image2](./images/task2img2.png)

`archive.ubuntu.com` should never be resolving to this IP address. You can also confirm that the IP, `203.0.113.108`, is suspicious by filtering for traffic by that IP and finding this interesting TCP stream

![image3](./images/task2img3.png)

That looks like some kind of public key transmitted, and something about the key being recieved? That doesn't look normal at all. 

This is actually a teaser for Task 5, and isn't needed to solve Task 2, so keep reading if you want to see where that leads!

From here, you were then supposed to hunt down the same config file we found earlier to find the other 2 IP addresses assigned to the device (that being `192.168.5.1` and `127.9.7.3`)

To conclude, I started looking at MACs using multiple IPs, but in reality you were supposed to use this malicious DNS query as the starting point of your investigation to then lead you to the correct config file (remember there are 2 other ones) and therefore the remaining two IPs. 

Cool stuff. Regardless of how we got there though, we got our task 2 badge. 

**Response:**
> Excellent work identifying the suspicious network traffic and narrowing in on the source! We will head over to the network administrators to discuss what we have discovered.