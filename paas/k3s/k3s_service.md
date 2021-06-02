# kubelet
k3s server和agent端都会运行kubelet

## api
kubelet自身也会提供api服务，监听如下两个端口
+ 127.0.0.1:10248
```
[root@shyi-1 ~]# curl http://127.0.0.1:10248/healthz
ok
``` 
+ [::]:10250 
```
[root@shyi-1 ~]# export CERT=/var/lib/rancher/k3s/server/tls/client-kube-apiserver.crt
[root@shyi-1 ~]# export KEY=/var/lib/rancher/k3s/server/tls/client-kube-apiserver.key
[root@shyi-1 ~]# http --cert $CERT --cert-key $KEY --verify /var/lib/rancher/k3s/agent/server-ca.crt https://192.168.1.105:10250/healthz
HTTP/1.1 200 OK
Content-Length: 2
Content-Type: text/plain; charset=utf-8
Date: Thu, 06 May 2021 11:22:36 GMT
X-Content-Type-Options: nosniff

ok
```

## static pod
在kubelet启动时会指定
```
Running kubelet --address=0.0.0.0 ... --pod-manifest-path=/var/lib/rancher/k3s/agent/pod-manifests
```

# kube-proxy
在k3s的server和agent节点都会运行kube-proxy
```
Running kube-proxy --cluster-cidr=10.42.0.0/16 --healthz-bind-address=127.0.0.1 --hostname-override=shyi-3.novalocal --kubeconfig=/var/lib/rancher/k3s/agent/kubeproxy.kubeconfig --proxy-mode=iptables
```

## api
kube-proxy本身也提供api接口，监听127.0.0.1:10249和127.0.0.1:10256
+ 127.0.0.1:10256为healthz端口
```
curl http://127.0.0.1:10256/healthz
```
+ 127.0.0.1:10249为metrics端口
```
curl http://127.0.0.1:10249/metrics
```

# kube-controller-manager

# cloud-controller-manager
参考
从 K8S 的 Cloud Provider 到 CCM 的演进之路
https://cloud.tencent.com/developer/article/1549964
使用Kubeadm在外部OpenStack云厂商部署Kubernetes集群
https://www.kubernetes.org.cn/6858.html
