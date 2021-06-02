# agent启动
```
K3S_DEBUG=true ./k3s.debug agent --server https://192.168.1.35:6443 --token K107322b943301d4eb6f6ba1d07b452f549884e22b4747f48779ca1abe9ec53d2f3::server:6ae34541048fa4f3ece7f7576ff895be 2>&1 | tee agent.log
```
指定日志级别
```
K3S_DEBUG=true ./k3s.debug agent -v 7 --server https://192.168.1.35:6443 --token K107322b943301d4eb6f6ba1d07b452f549884e22b4747f48779ca1abe9ec53d2f3::server:6ae34541048fa4f3ece7f7576ff895be 2>&1 | tee agent.log
```
k3s agent运行的服务
+ load balancer
```
Running load balancer 127.0.0.1:36633 -> [192.168.1.35:6443]
```
+ containerd
```
Running containerd -c /var/lib/rancher/k3s/agent/etc/containerd/config.toml -a /run/k3s/containerd/containerd.sock --state /run/k3s/containerd --root /var/lib/rancher/k3s/agent/containerd
```
+ kubelet
```
Running kubelet --address=0.0.0.0 --anonymous-auth=false --authentication-token-webhook=true --authorization-mode=Webhook --cgroup-driver=cgroupfs --client-ca-file=/var/lib/rancher/k3s/agent/client-ca.crt --cloud-provider=external --cluster-dns=10.43.0.10 --cluster-domain=cluster.local --cni-bin-dir=/var/lib/rancher/k3s/data/2503e97adc21f7ca3dd20cf02763094a927edd24e4b9bd38b87a2f99eb10fa2e/bin --cni-conf-dir=/var/lib/rancher/k3s/agent/etc/cni/net.d --container-runtime-endpoint=unix:///run/k3s/containerd/containerd.sock --container-runtime=remote --containerd=/run/k3s/containerd/containerd.sock --eviction-hard=imagefs.available<5%,nodefs.available<5% --eviction-minimum-reclaim=imagefs.available=10%,nodefs.available=10% --fail-swap-on=false --healthz-bind-address=127.0.0.1 --hostname-override=shyi-3.novalocal --kubeconfig=/var/lib/rancher/k3s/agent/kubelet.kubeconfig --kubelet-cgroups=/k3s --node-labels= --pod-manifest-path=/var/lib/rancher/k3s/agent/pod-manifests --read-only-port=0 --resolv-conf=/etc/resolv.conf --serialize-image-pulls=false --tls-cert-file=/var/lib/rancher/k3s/agent/serving-kubelet.crt --tls-private-key-file=/var/lib/rancher/k3s/agent/serving-kubelet.key
```
+ kube-proxy
```
Running kube-proxy --cluster-cidr=10.42.0.0/16 --healthz-bind-address=127.0.0.1 --hostname-override=shyi-3.novalocal --kubeconfig=/var/lib/rancher/k3s/agent/kubeproxy.kubeconfig --proxy-mode=iptables
```
使用bpftrace查看k3s agent启动过程中所执行的命令
```
BPFTRACE_STRLEN=200 bpftrace -e 'tracepoint:syscalls:sys_enter_execve {printf("[ %d %s ]=> %s ", pid, comm, str(args->filename)); join(args->argv);}'
```
查看containerd程序的执行情况
```
BEGIN {
    printf("Begin!\n");
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/pkg/agent/proxy.NewAPIProxy" {
    // printf("%d %s %s: %d %d %d %d %d %d\n", pid, comm, func, (uint8)sarg0, sarg1, sarg2, sarg3, sarg4, sarg5);
    printf("[%d %s %s] enabled:%d dataDir:%s url:%s port:%d\n",
        pid, comm, func, (uint8)sarg0, str(sarg1, sarg2), str(sarg3, sarg4), sarg5);
    // printf("%s\n", ustack(perf));
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/pkg/agent/tunnel.connect" {
    printf("[%d %s %s]\n", pid, comm, func);
    // printf("%s\n", ustack(perf));
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/vendor/github.com/rancher/remotedialer.ClientConnect" {
    printf("[%d %s %s] wsURL:%s\n", pid, comm, func, str(sarg2, sarg3));
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/vendor/github.com/rancher/remotedialer.(*Session).Serve" {
    printf("[%d %s %s]\n", pid, comm, func);
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/vendor/github.com/rancher/remotedialer.(*Session).serveMessage" {
    printf("[%d %s %s]\n", pid, comm, func);
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/pkg/daemons/agent.startKubelet" {
    printf("[%d %s %s]\n", pid, comm, func);
    printf("%s\n", ustack(perf));
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/vendor/k8s.io/kubernetes/pkg/kubelet/config.NewSourceApiserver" {
    printf("[%d %s %s] nodeName:%s\n", pid, comm, func, str(sarg2, sarg3));
    // printf("%s\n", ustack(perf));
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/vendor/k8s.io/kubernetes/pkg/kubelet.NewMainKubelet" {
    printf("[%d %s %s] containerRuntime:%s hostname:%s\n", pid, comm, func, str(sarg3, sarg4), str(sarg5, sarg6));
    // printf("%s\n", ustack(perf));
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/vendor/google.golang.org/grpc.NewServer" {
    printf("[%d %s %s]\n", pid, comm, func);
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/vendor/github.com/containerd/cri/pkg/server.(*criService).RunPodSandbox" {
    printf("[%d %s %s]\n", pid, comm, func);
}
```

## tunnel-proxy
tunnel-proxy
```
bpftrace -e 'uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/pkg/agent/tunnel*" {printf("%d %s %s\n", pid, comm, probe);}'
```

sarg0为*(reg("sp") + 8)，sarg0为*(reg("sp") + 16)，golang中interface类型为struct
```
struct runtime.iface {
    runtime.itab *tab;
    void *data;
}
```
查看github.com/rancher/k3s/pkg/agent/tunnel.connect函数的参数
+ rootCtx: sarg0, sarg1
+ waitGroup: sarg2
+ address: sarg3, sarg4
+ tlsConfig: sarg5
```
bpftrace -e 'uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/pkg/agent/tunnel.connect" {$arr = reg("sp") + 32; $len = *(reg("sp") + 40); printf("%s\n", str(*($arr), $len)); printf("%s\n", str(sarg3, sarg4));}'
```

## http
```
BPFTRACE_STRLEN=144 bpftrace -e 'uprobe:/var/lib/rancher/k3s/data/fc6dd3231f937e15dcaa455aa88ab7f385584efe2db352f0d3473152fb14e3fd/bin/containerd:"net/http.NewRequestWithContext" {printf("[%d %s %s] method:%s url:%s\n", pid, comm, func, str(sarg2, sarg3), str(sarg4, sarg5));}'
```
通过本地的代理发向api-server，k3s agent启动日志
```
time="2021-04-12T09:36:12.337458994Z" level=info msg="Running load balancer 127.0.0.1:44511 -> [192.168.1.35:6443]"
```
bpftrace脚本
```
// BPFTRACE_STRLEN=144 bpftrace do_http.bt
BEGIN {
    printf("Begin\n");
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"net/http.NewRequestWithContext" {
    printf("[%d %s %s] method:%s url:%s\n", pid, comm, func, str(sarg2, sarg3), str(sarg4, sarg5));
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"net.(*Dialer).DialContext" {
    printf("[%d %s %s] net:%s address:%s\n", pid, comm, func, str(sarg3, sarg4), str(sarg5, sarg6));
}

/*
uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/vendor/github.com/google/tcpproxy.*" {
    printf("[%d %s %s]\n", pid, comm, func);
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"net.Listen" {
    printf("[%d %s %s]\n", pid, comm, func);
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"net.(*TCPListener).*" {
    printf("[%d %s %s]\n", pid, comm, func);
}

uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"net.(*TCPConn).*" {
    printf("[%d %s %s]\n", pid, comm, func);
}
*/
```

# flannel网络
flannel使用vxlan，对于新加入的agent节点，在agent节点查看网络信息
```
[root@shyi-3 ~]# ip -o link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000\    link/ether fa:16:3e:80:b5:b9 brd ff:ff:ff:ff:ff:ff
3: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400 qdisc noqueue state UNKNOWN mode DEFAULT group default \    link/ether f2:1b:66:71:45:6e brd ff:ff:ff:ff:ff:ff
4: cni0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400 qdisc noqueue state UP mode DEFAULT group default qlen 1000\    link/ether 6a:b2:33:9b:fb:7d brd ff:ff:ff:ff:ff:ff
5: veth3bba095b@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400 qdisc noqueue master cni0 state UP mode DEFAULT group default \    link/ether 6a:3f:89:ea:f3:3e brd ff:ff:ff:ff:ff:ff link-netnsid 0
[root@shyi-3 ~]# ip -o addr
1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
2: eth0    inet 192.168.1.105/24 brd 192.168.1.255 scope global dynamic eth0\       valid_lft 84538sec preferred_lft 84538sec
2: eth0    inet6 fe80::f816:3eff:fe80:b5b9/64 scope link \       valid_lft forever preferred_lft forever
3: flannel.1    inet 10.42.1.0/32 scope global flannel.1\       valid_lft forever preferred_lft forever
3: flannel.1    inet6 fe80::f01b:66ff:fe71:456e/64 scope link \       valid_lft forever preferred_lft forever
4: cni0    inet 10.42.1.1/24 brd 10.42.1.255 scope global cni0\       valid_lft forever preferred_lft forever
4: cni0    inet6 fe80::68b2:33ff:fe9b:fb7d/64 scope link \       valid_lft forever preferred_lft forever
5: veth3bba095b    inet6 fe80::683f:89ff:feea:f33e/64 scope link \       valid_lft forever preferred_lft forever
```
+ 发现多了三个网络设备flannel.1、cni0和veth3bba095b
+ eth0 ip为192.168.1.105/24
+ flannel.1 ip为10.42.1.0/32
+ cni0 ip为10.42.1.1/24

## vxlan
+ flannel.1 为vxlan设备，查看flannel.1的bridge fdb
```
[root@shyi-3 ~]# ip -d link show flannel.1
3: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400 qdisc noqueue state UNKNOWN mode DEFAULT group default
    link/ether f2:1b:66:71:45:6e brd ff:ff:ff:ff:ff:ff promiscuity 0
    vxlan id 1 local 192.168.1.105 dev eth0 srcport 0 0 dstport 8472 nolearning ageing 300 udpcsum noudp6zerocsumtx noudp6zerocsumrx addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
[root@shyi-3 ~]# bridge fdb show dev flannel.1
4e:ae:5e:af:01:17 dst 192.168.1.35 self permanent
```
    + local ip为eth0的ip 192.168.1.105
    + dstport为8472
    + 192.168.1.35为server的eth0 ip，4e:ae:5e:af:01:17为server上flannel.1的mac
+ cni0 为bridge
```
[root@shyi-3 ~]# brctl show
bridge name     bridge id               STP enabled     interfaces
cni0            8000.6ab2339bfb7d       no              veth3bba095b
```
+ veth3bba095b 为veth，查看veth pair的ifindex
```
[root@shyi-3 ~]# ethtool -S veth3bba095b
NIC statistics:
     peer_ifindex: 3
```
+ 查看路由信息
```
[root@shyi-3 ~]# ip route
default via 192.168.1.1 dev eth0
10.42.0.0/24 via 10.42.0.0 dev flannel.1 onlink
10.42.1.0/24 dev cni0 proto kernel scope link src 10.42.1.1
169.254.169.254 via 192.168.1.2 dev eth0 proto static
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.105
```
    + server节点的flannel.1 ip为10.42.0.0/32，cni0 ip为10.42.0.1/24
    + 访问本节点上pod，通过cni0桥路由
    + 访问server节点上pod，根据路由通过flannel.1的vxlan传输

## trace
通过trace-cmd命令查看fdb信息的添加
```
trace-cmd record -p function -l '*fdb*:mod:vxlan' -e 'bridge:*'
```
agent启动后通过trace-cmd report查看
```
 k3s-agent-1559  [006]   552.243386: function:             vxlan_fdb_add
 k3s-agent-1559  [006]   552.243400: function:                vxlan_fdb_parse
 k3s-agent-1559  [006]   552.243401: function:                vxlan_fdb_update
 k3s-agent-1559  [006]   552.243401: function:                   vxlan_fdb_create
 k3s-agent-1559  [006]   552.243402: function:                      vxlan_fdb_find_rdst
 k3s-agent-1559  [006]   552.243402: function:                      vxlan_fdb_append.part.55
 k3s-agent-1559  [006]   552.243405: function:                   vxlan_fdb_notify
 k3s-agent-1559  [006]   552.243406: function:                      vxlan_fdb_info
    bridge-1831  [002]   561.230445: fdb_delete:           br_dev cni0 dev null addr 2e:c4:83:4b:68:be vid 1
    bridge-1842  [005]   561.362721: br_fdb_update:        br_dev cni0 source vethfde5f38f addr ca:98:8b:1a:32:13 vid 0 added_by_user 0
```
