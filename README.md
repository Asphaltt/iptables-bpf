# 该如此玩转 iptables-bpf

在看 [iptables-nfqueue](https://asphaltt.github.io/post/iptables-nfqueue/) 源代码的时候，发现 iptables 有 bpf 特性，于是查了下 `iptables-bpf` 的资料。

- [使用iptables的bpf match来优化规则集-HiPAC/ipset/n+1模型之外的方法](https://blog.csdn.net/dog250/article/details/77790504)
- [HOW WE USED EBPF TO BUILD PROGRAMMABLE PACKET FILTERING IN MAGIC FIREWALL](https://noise.getoto.net/2021/12/06/how-we-used-ebpf-to-build-programmable-packet-filtering-in-magic-firewall/)
- [iptables-extensions](https://ipset.netfilter.org/iptables-extensions.man.html)

`iptables-bpf` 资料甚少，bpf 资料 [ebpf.io](https://ebpf.io)、 [ebpf.top](https://ebpf.top)。看了 dog250 大神的玩法，心疼大神一两秒，扣 bpf 字节码不是小弟能够企及的。

```txt
bpf

Match using Linux Socket Filter. Expects a path to an eBPF object or a cBPF program in decimal format.

--object-pinned path
		Pass a path to a pinned eBPF object.
		
Applications load eBPF programs into the kernel with the bpf() system call and BPF_PROG_LOAD command and can pin them in a virtual filesystem with BPF_OBJ_PIN. To use a pinned object in iptables, mount the bpf filesystem using

		mount -t bpf bpffs ${BPF_MOUNT}

then insert the filter in iptables by path:

		iptables -A OUTPUT -m bpf --object-pinned ${BPF_MOUNT}/{PINNED_PATH} -j ACCEPT
```

这才是我想要的。编写一个 `socket` bpf 程序才是我在行的。

> 源代码：[github.com/Asphaltt/iptables-bpf](https://github.com/Asphaltt/iptables-bpf)

## bpf 程序怎么能少了 bpf map

不能将 IP 地址写死在 bpf 程序里，那就将 IP 地址放到 bpf map 里。源代码如下：

```c
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, u32);
	__type(value, u8);
} filter_daddrs SEC(".maps");

SEC("socket")
int filter_iptables(void *skb) {
	struct iphdr iph;
	u8 *filtered;

	if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph), BPF_HDR_START_NET) < 0)
		return BPF_OK;

	filtered = bpf_map_lookup_elem(&filter_daddrs, &iph.daddr);
	if (filtered != NULL && *filtered == 1)
		return BPF_DROP;

	return BPF_OK;
}
```

`iptables -I OUTPUT -m bpf --object-pinned $(EBPF_PINNED) -j DROP` 里使用这个 bpf 程序，将 bpf map 里匹配到的目的地址的网络包都 drop 掉。效果如下：

```bash
# ping -c4 223.5.5.5
PING 223.5.5.5 (223.5.5.5) 56(84) bytes of data.
64 bytes from 223.5.5.5: icmp_seq=1 ttl=63 time=167 ms
64 bytes from 223.5.5.5: icmp_seq=2 ttl=63 time=159 ms
64 bytes from 223.5.5.5: icmp_seq=3 ttl=63 time=1047 ms

--- 223.5.5.5 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss, time 3081ms
rtt min/avg/max/mdev = 158.744/457.539/1047.019/416.838 ms, pipe 2

# make
clang -I./bpf/headers -O2 -g -target bpf -c bpf/iptables-bpf.c  -o iptables-bpf.elf
go build -v -o iptables-bpf main.go

# make setup
bpftool prog load iptables-bpf.elf /sys/fs/bpf/iptbpf
iptables -I OUTPUT -m bpf --object-pinned /sys/fs/bpf/iptbpf -j DROP

# make mapid
986

#./iptables-bpf -m 986 -d 223.5.5.5
2021/12/16 15:18:49 223.5.5.5 can't be pinged

# ping -c4 223.5.5.5
PING 223.5.5.5 (223.5.5.5) 56(84) bytes of data.

--- 223.5.5.5 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3065ms

# make clean
rm -f iptables-bpf.elf
rm -f iptables-bpf
iptables -D OUTPUT -m bpf --object-pinned /sys/fs/bpf/iptbpf -j DROP
rm -f /sys/fs/bpf/iptbpf

# ping -c4 223.5.5.5
PING 223.5.5.5 (223.5.5.5) 56(84) bytes of data.
64 bytes from 223.5.5.5: icmp_seq=1 ttl=63 time=139 ms
64 bytes from 223.5.5.5: icmp_seq=2 ttl=63 time=157 ms
64 bytes from 223.5.5.5: icmp_seq=3 ttl=63 time=169 ms
64 bytes from 223.5.5.5: icmp_seq=4 ttl=63 time=121 ms

--- 223.5.5.5 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3087ms
rtt min/avg/max/mdev = 120.720/146.495/168.600/18.163 ms
```

## 管理 bpf map

困难山头已经跨过，剩下个小山头。

使用 bpftool 工具人肉来管理 bpf map？不可能的，用 Go 来管理吧。

```go
func main() {

	var daddr string
	var bpfMap int
	flag.StringVar(&daddr, "d", "", "ip addresses to drop, separated by ','")
	flag.IntVar(&bpfMap, "m", 0, "the id of the bpf map(filter_daddrs)")
	flag.Parse()

	var ips []netaddr.IP
	addrs := strings.FieldsFunc(daddr, func(r rune) bool { return r == ',' })
	for _, addr := range addrs {
		ip, err := netaddr.ParseIP(addr)
		if err != nil {
			log.Fatalf("%s is not a valid IPv4 address", ip)
		}

		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		log.Fatalf("no ip address(es) to be dropped")
	}

	m, err := ebpf.NewMapFromID(ebpf.MapID(bpfMap))
	if err != nil {
		log.Fatalf("bpf map(%d) not found, err: %v", bpfMap, err)
	}

	val := uint8(1)
	for _, ip := range ips {
		_ip := ip.As4()
		ipval := binary.LittleEndian.Uint32(_ip[:])
		if err := m.Update(ipval, val, ebpf.UpdateAny); err != nil {
			log.Fatalf("failed to upsert data to bpf map(%d), err: %v", bpfMap, err)
		}
	}

	log.Printf("%s can't be pinged", daddr)
}
```

使用 Go 来管理 bpf map，将 `iptables-bpf` 的易用性提升了一个台阶。相比于单纯的 iptables 规则，`iptables-bpf` 给 iptables 带来了无与伦比的可编程性。

## 实验环境

```bash
# lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 21.04
Release:        21.04
Codename:       hirsute

# uname -a
Linux pagani 5.11.0-31-generic #33-Ubuntu SMP Wed Aug 11 13:19:04 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

### iptables

有的 iptables 默认带有 bpf 特性，有的没带。如果没带，则在执行 `iptables -I OUTPUT -m bpf --object-pinned /sys/fs/bpf/iptbpf -j DROP` 的时候，提示 `iptables v1.6.1: No bpf header, kernel headers too old?`。需要重新编译 iptables。

```bash
git clone git://git.netfilter.org/iptables.git
cd iptables
bash autogen.sh
apt install -y libpcap-dev # bpf 依赖 libpcap
./configure --enable-bpf-compiler --disable-nftables # disable nftables 是为了快速安装一个能用 bpf 的 iptables
# 留意结果
Iptables Configuration:
  ...
  BPF utils support:                    yes

make -j4
make install
# 此时 iptables 已开启 bpf 特性
```

## 总结

bpf 带给了 iptables 不少想象力，只是目前还没有释放出来。

如果使用 `iptables-bpf` 实现 iptables 的匹配能力，该如何在 bpf 程序里实现一个高性能的匹配算法呢？

