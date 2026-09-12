# Результаты

### Фрагментация в IPv4

| Тип пакета                | Условие                | BPF-фильтр                                        | Пояснение                                                                                     |
|---------------------------|------------------------|---------------------------------------------------|-----------------------------------------------------------------------------------------------|
| Первый фрагмент           | `Offset = 0`, `MF = 1` | `ip[6:2] & 0x1FFF = 0 and ip[6:2] & 0x2000 != 0`  | Смещение равно 0, но установлен `More Fragments`, значит это начало фрагментированного пакета |
| Средний фрагмент          | `Offset > 0`, `MF = 1` | `ip[6:2] & 0x1FFF != 0 and ip[6:2] & 0x2000 != 0` | Уже есть смещение и после этого фрагмента будут ещё фрагменты                                 |
| Последний фрагмент        | `Offset > 0`, `MF = 0` | `ip[6:2] & 0x1FFF != 0 and ip[6:2] & 0x2000 = 0`  | Смещение ненулевое, но `MF` сброшен — продолжения больше нет                                  |
| Нефрагментированный пакет | `Offset = 0`, `MF = 0` | `ip[6:2] & 0x1FFF = 0 and ip[6:2] & 0x2000 = 0`   | Нет смещения и нет последующих фрагментов                                                     |

### Захват трафика

#### 3 TCP-сессии

```bash
tcpdump -nn -r lab2.pcap 'host 142.251.150.4 and port 57507'
 
reading from file lab2.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:29:17.517862 IP 192.168.81.222.57507 > 142.251.150.4.443: Flags [SEW], seq 318179212, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 3420494806 ecr 0,sackOK,eol], length 0
21:29:17.549421 IP 142.251.150.4.443 > 192.168.81.222.57507: Flags [S.], seq 2181151758, ack 318179213, win 65535, options [mss 1412,sackOK,TS val 1337518394 ecr 3420494806,nop,wscale 8], length 0
21:29:17.549664 IP 192.168.81.222.57507 > 142.251.150.4.443: Flags [.], ack 1, win 2057, options [nop,nop,TS val 3420494838 ecr 1337518394], length 0
```

```bash
tcpdump -nn -r lab2.pcap 'host 142.251.150.4 and port 57421'

reading from file lab2.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:28:37.518515 IP 192.168.81.222.57421 > 142.251.150.4.443: Flags [SEW], seq 2337830900, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 873525116 ecr 0,sackOK,eol], length 0
21:28:37.560683 IP 142.251.150.4.443 > 192.168.81.222.57421: Flags [S.], seq 1022951405, ack 2337830901, win 65535, options [mss 1412,sackOK,TS val 3340729340 ecr 873525116,nop,wscale 8], length 0
21:28:37.560872 IP 192.168.81.222.57421 > 142.251.150.4.443: Flags [.], ack 1, win 2057, options [nop,nop,TS val 873525159 ecr 3340729340], length 0
```

```bash
tcpdump -nn -r lab2.pcap 'host 142.251.150.4 and port 57422'

reading from file lab2.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:28:39.279045 IP 192.168.81.222.57422 > 142.251.150.4.443: Flags [SEW], seq 3821369812, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 1789032124 ecr 0,sackOK,eol], length 0
21:28:39.309998 IP 142.251.150.4.443 > 192.168.81.222.57422: Flags [S.], seq 3087967241, ack 3821369813, win 65535, options [mss 1412,sackOK,TS val 3054664748 ecr 1789032124,nop,wscale 8], length 0
21:28:39.310147 IP 192.168.81.222.57422 > 142.251.150.4.443: Flags [.], ack 1, win 2057, options [nop,nop,TS val 1789032155 ecr 3054664748], length 0
```

#### DNS-запрос

```bash
tcpdump -nn -r lab2.pcap 'udp port 53' | grep -i 'google.com'

reading from file lab2.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:28:49.936072 IP 192.168.81.222.18528 > 192.168.64.10.53: 55851+ HTTPS? play.google.com. (33)
21:28:49.936264 IP 192.168.81.222.50439 > 192.168.64.10.53: 39132+ A? play.google.com. (33)
21:28:59.444228 IP 192.168.81.222.52341 > 192.168.64.10.53: 4256+ [1au] A? google.com. (39)
21:29:11.450133 IP 192.168.81.222.63571 > 192.168.64.11.53: 61808+ A? google.com. (28)
```

#### ICMP-пакет

```bash
tcpdump -nn -r lab2.pcap 'icmp and host 8.8.8.8'

reading from file lab2.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:28:47.636552 IP 192.168.81.222 > 8.8.8.8: ICMP echo request, id 35733, seq 0, length 64
21:28:47.667140 IP 8.8.8.8 > 192.168.81.222: ICMP echo reply, id 35733, seq 0, length 64
21:28:48.643705 IP 192.168.81.222 > 8.8.8.8: ICMP echo request, id 35733, seq 1, length 64
21:28:48.674294 IP 8.8.8.8 > 192.168.81.222: ICMP echo reply, id 35733, seq 1, length 64
21:28:49.646382 IP 192.168.81.222 > 8.8.8.8: ICMP echo request, id 35733, seq 2, length 64
21:28:49.677627 IP 8.8.8.8 > 192.168.81.222: ICMP echo reply, id 35733, seq 2, length 64
```

#### Самый большой по размеру пакет

```bash
tcpdump -nn -v -r lab2.pcap ip 2>/dev/null |
awk '{
    for (i = 1; i <= NF; i++) {
        if ($i == "length") {
            len = $(i + 1)
            gsub(/[^0-9]/, "", len)
            print len "\t" $0
            break
        }
    }
}' |
sort -k1,1nr |
head -n 1

1500	21:28:43.924801 IP (tos 0x2,ECT(0), ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 1500)
```

Самый большой IPv4-пакет в дампе имеет размер 1500 байт