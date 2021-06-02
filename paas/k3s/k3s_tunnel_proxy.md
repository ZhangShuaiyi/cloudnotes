环境
使用外部etcd部署两个master的k3s高可用集群，使用haproxy代理两个master节点的api-server
+ haproxy节点：192.168.1.177，端口使用6789
+ k3s master 1节点：192.168.1.229
+ k3s master 2节点：192.168.1.63
+ 两个k3smaster节点上k3s服务的配置文件/etc/systemd/system/k3s.service.env内容为
```
K3S_DEBUG=true
CATTLE_TUNNEL_DATA_DEBUG=true
K3S_TOKEN=token123456
K3S_DATASTORE_ENDPOINT="http://<etcd节点ip>:2379"
```
+ haproxy.cfg配置文件内容
```
frontend k3s
    bind 192.168.1.177:6789
    option tcplog
    mode tcp
    default_backend k3s-api

backend k3s-api
    mode tcp
    balance roundrobin
    option tcp-check
    server k3s-master-0 192.168.1.229:6443 check fall 3 rise 2
    server k3s-master-1 192.168.1.63:6443 check fall 3 rise 2
```
+ agent命令
```
K3S_DEBUG=true ./k3s agent --server https://192.168.1.177:6789 --token <node-token>
```

# loadbalancer
agent端loadbalancer配置文件"/var/lib/rancher/k3s/agent/etc/k3s-agent-load-balancer.json"，内容为
```json
{
  "ServerURL": "https://192.168.1.177:6789",
  "ServerAddresses": [
    "192.168.1.229:6443",
    "192.168.1.63:6443"
  ],
  "Listener": null
}
```

## 配置文件为空
查看github.com/rancher/k3s/pkg/agent/loadbalancer.New的调用情况
```
[26542 k3s-agent github.com/rancher/k3s/pkg/agent/loadbalancer.New] dir:/var/lib/rancher/k3s/agent service:k3s-agent-load-balancer url:https://192.168.1.177:6789 port:0

        1789060 github.com/rancher/k3s/pkg/agent/loadbalancer.New+0 (/var/lib/rancher/k3s/data/current/bin/containerd)
        3574cce github.com/rancher/k3s/pkg/agent.Run+366 (/var/lib/rancher/k3s/data/current/bin/containerd)
        3577e9d github.com/rancher/k3s/pkg/cli/agent.Run+925 (/var/lib/rancher/k3s/data/current/bin/containerd)
        178fdbd github.com/rancher/k3s/vendor/github.com/urfave/cli.HandleAction+253 (/var/lib/rancher/k3s/data/current/bin/containerd)
        1790b8e github.com/rancher/k3s/vendor/github.com/urfave/cli.Command.Run+1422 (/var/lib/rancher/k3s/data/current/bin/containerd)
        178dcb4 github.com/rancher/k3s/vendor/github.com/urfave/cli.(*App).Run+2004 (/var/lib/rancher/k3s/data/current/bin/containerd)
        3b05b3a main.main+2650 (/var/lib/rancher/k3s/data/current/bin/containerd)
        43b909 runtime.main+521 (/var/lib/rancher/k3s/data/current/bin/containerd)
        472281 runtime.goexit+1 (/var/lib/rancher/k3s/data/current/bin/containerd)
```
使用addr2line查看对应源码
```
[root@shyi-3 ~]# echo 3574cce | go tool addr2line /var/lib/rancher/k3s/data/current/bin/containerd
github.com/rancher/k3s/pkg/agent.Run
/go/src/github.com/rancher/k3s/pkg/agent/run.go:147
```
对应代码内容为
```go
	proxy, err := proxy.NewAPIProxy(!cfg.DisableLoadBalancer, agentDir, cfg.ServerURL, cfg.LBServerPort)
	if err != nil {
		return err
	}
```
在loadbalancer.New中使用tcpproxy库实现lb功能，在lb.dialContext中调用net.(*Dialer).DialContext建立tcp连接
```go
	lb.proxy.AddRoute(serviceName, &tcpproxy.DialProxy{
		Addr:        serviceName,
		DialContext: lb.dialContext,
		OnDialError: onDialError,
	})
```
在pkg/agent/config.Get中通过lb建立的tcpproxy访问api-server，http请求访问走local端口，如
```
https://127.0.0.1:45211/cacerts
https://127.0.0.1:45211/v1-k3s/config
```
Get /cacerts是免密的，验证
```
[root@shyi-3 ]# curl -k https://192.168.1.177:6789/cacerts
-----BEGIN CERTIFICATE-----
MIIBeDCCAR2gAwIBAgIBADAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhrM3Mtc2Vy
dmVyLWNhQDE2MTg0MDYyOTIwHhcNMjEwNDE0MTMxODEyWhcNMzEwNDEyMTMxODEy
WjAjMSEwHwYDVQQDDBhrM3Mtc2VydmVyLWNhQDE2MTg0MDYyOTIwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAAQ7o4Vc8o/ZNhm1LqyMDIGqV37Ee8iciJ+AJ/HVtzhc
8WlZqszKtSZsEP3H9wfe+0g5yf+pw7i1ogHZjCSjXt5Wo0IwQDAOBgNVHQ8BAf8E
BAMCAqQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUSP9X/itFPwWajuc2MKte
Tfugg/YwCgYIKoZIzj0EAwIDSQAwRgIhAJcTy+lLuUTviU0J6tahYCXlHJzDXyRW
b0os5wJnZfZpAiEAzRZ6JsPnfqLHPyPF3Q4mmjbiTtJS3P5DeuaADq2qKLM=
-----END CERTIFICATE-----
``` 

## load balancer更新
由于agent命令行指定的为haproxy代理的地址，在github.com/rancher/k3s/pkg/agent/tunnel.Setup中会通过api查看集群endpoints信息
```go
	endpoint, _ := client.CoreV1().Endpoints("default").Get(ctx, "kubernetes", metav1.GetOptions{})
	if endpoint != nil {
		addresses := getAddresses(endpoint)
		if len(addresses) > 0 {
			proxy.Update(getAddresses(endpoint))
		}
	}
```
等价于命令行
```
[root@shyi-4 ~]# kubectl get endpoints kubernetes -n default
NAME         ENDPOINTS                              AGE
kubernetes   192.168.1.229:6443,192.168.1.63:6443   20h
```
调用proxy.Update==>LoadBalancer.Update==>LoadBalancer.setServers更新lb信息。**此时k3s api还是通过lb的tcpproxy代理**

## api请求
通过kubectl命令查看ca信息
```
kubectl config view --raw
```
获取cert
```
kubectl config view --raw -o jsonpath='{.users[0].user.client-certificate-data}' | base64 -d
```
获取key
```
kubectl config view --raw -o jsonpath='{.users[0].user.client-key-data}' | base64 -d
```

在agent节点中使用wget验证agent lb绑定的本地端口
```
wget -q -O - --ca-certificate=/var/lib/rancher/k3s/agent/server-ca.crt --certificate=./test.cert --private-key=./test.key https://127.0.0.1:36033/
wget -q -O - --no-check-certificate --certificate=./test.cert --private-key=./test.key https://127.0.0.1:36033/
```
不使用curl命令验证原因，curl命令不支持"EC PRIVATE KEY"，使用curl报错SEC_ERROR_BAD_KEY
```
curl: (58) unable to load client key: -8178 (SEC_ERROR_BAD_KEY)
```
可以使用python2-httpie进行验证
```
http --cert ./test.cert --cert-key test.key --verify /var/lib/rancher/k3s/agent/server-ca.crt https://127.0.0.1:36033/
```
