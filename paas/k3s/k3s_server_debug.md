# server启动

使用k3s脚本安装k3s时会配置k3s.service，通过/etc/systemd/system/k3s.service.env可配置k3s
```
K3S_DEBUG=true
```

## 启动的服务
通过日志查看k3s server启动如下服务
+ kube-apiserver
```
Running kube-apiserver --advertise-port=6443 --allow-privileged=true --anonymous-auth=false --api-audiences=unknown --authorization-mode=Node,RBAC --bind-address=127.0.0.1 --cert-dir=/var/lib/rancher/k3s/server/tls/temporary-certs --client-ca-file=/var/lib/rancher/k3s/server/tls/client-ca.crt --enable-admission-plugins=NodeRestriction --etcd-servers=unix://kine.sock --feature-gates=ServiceAccountIssuerDiscovery=false --insecure-port=0 --kubelet-certificate-authority=/var/lib/rancher/k3s/server/tls/server-ca.crt --kubelet-client-certificate=/var/lib/rancher/k3s/server/tls/client-kube-apiserver.crt --kubelet-client-key=/var/lib/rancher/k3s/server/tls/client-kube-apiserver.key --profiling=false --proxy-client-cert-file=/var/lib/rancher/k3s/server/tls/client-auth-proxy.crt --proxy-client-key-file=/var/lib/rancher/k3s/server/tls/client-auth-proxy.key --requestheader-allowed-names=system:auth-proxy --requestheader-client-ca-file=/var/lib/rancher/k3s/server/tls/request-header-ca.crt --requestheader-extra-headers-prefix=X-Remote-Extra- --requestheader-group-headers=X-Remote-Group --requestheader-username-headers=X-Remote-User --secure-port=6444 --service-account-issuer=k3s --service-account-key-file=/var/lib/rancher/k3s/server/tls/service.key --service-account-signing-key-file=/var/lib/rancher/k3s/server/tls/service.key --service-cluster-ip-range=10.43.0.0/16 --service-node-port-range=30000-32767 --storage-backend=etcd3 --tls-cert-file=/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt --tls-private-key-file=/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.key
```
+ kube-scheduler
```
Running kube-scheduler --address=127.0.0.1 --bind-address=127.0.0.1 --kubeconfig=/var/lib/rancher/k3s/server/cred/scheduler.kubeconfig --leader-elect=false --port=10251 --profiling=false --secure-port=0
```
+ kube-controller-manager
```
Running kube-controller-manager --address=127.0.0.1 --allocate-node-cidrs=true --bind-address=127.0.0.1 --cluster-cidr=10.42.0.0/16 --cluster-signing-cert-file=/var/lib/rancher/k3s/server/tls/client-ca.crt --cluster-signing-key-file=/var/lib/rancher/k3s/server/tls/client-ca.key --configure-cloud-routes=false --controllers=*,-service,-route,-cloud-node-lifecycle --kubeconfig=/var/lib/rancher/k3s/server/cred/controller.kubeconfig --leader-elect=false --port=10252 --profiling=false --root-ca-file=/var/lib/rancher/k3s/server/tls/server-ca.crt --secure-port=0 --service-account-private-key-file=/var/lib/rancher/k3s/server/tls/service.key --use-service-account-credentials=true
```
+ containerd
```
Running containerd -c /var/lib/rancher/k3s/agent/etc/containerd/config.toml -a /run/k3s/containerd/containerd.sock --state /run/k3s/containerd --root /var/lib/rancher/k3s/agent/containerd
```
+ cloud-controller-manager
```
Running cloud-controller-manager for provider k3s with args --profiling=false
```
+ kubelet
```
Running kubelet --address=0.0.0.0 --anonymous-auth=false --authentication-token-webhook=true --authorization-mode=Webhook --cgroup-driver=cgroupfs --client-ca-file=/var/lib/rancher/k3s/agent/client-ca.crt --cloud-provider=external --cluster-dns=10.43.0.10 --cluster-domain=cluster.local --cni-bin-dir=/var/lib/rancher/k3s/data/2503e97adc21f7ca3dd20cf02763094a927edd24e4b9bd38b87a2f99eb10fa2e/bin --cni-conf-dir=/var/lib/rancher/k3s/agent/etc/cni/net.d --container-runtime-endpoint=unix:///run/k3s/containerd/containerd.sock --container-runtime=remote --containerd=/run/k3s/containerd/containerd.sock --eviction-hard=imagefs.available<5%,nodefs.available<5% --eviction-minimum-reclaim=imagefs.available=10%,nodefs.available=10% --fail-swap-on=false --healthz-bind-address=127.0.0.1 --hostname-override=shyi-1.novalocal --kubeconfig=/var/lib/rancher/k3s/agent/kubelet.kubeconfig --node-labels= --pod-manifest-path=/var/lib/rancher/k3s/agent/pod-manifests --read-only-port=0 --resolv-conf=/etc/resolv.conf --serialize-image-pulls=false --tls-cert-file=/var/lib/rancher/k3s/agent/serving-kubelet.crt --tls-private-key-file=/var/lib/rancher/k3s/agent/serving-kubelet.key
```
+ kube-proxy
```
Running kube-proxy --cluster-cidr=10.42.0.0/16 --healthz-bind-address=127.0.0.1 --hostname-override=shyi-1.novalocal --kubeconfig=/var/lib/rancher/k3s/agent/kubeproxy.kubeconfig --proxy-mode=iptables
```

## 启动流程
在github.com/rancher/k3s/pkg/daemons/control.Server中通过apiServer,scheduler,controllerManager,cloudControllerManager启动相应的k8s服务，实际调用函数为
+ github.com/rancher/k3s/pkg/daemons/executor.Embedded.APIServer
+ github.com/rancher/k3s/pkg/daemons/executor.Embedded.Scheduler
+ github.com/rancher/k3s/pkg/daemons/executor.Embedded.ControllerManager
k3s通过Goroutine启动相应的k8s组件
```go
func (Embedded) APIServer(ctx context.Context, etcdReady <-chan struct{}, args []string) (authenticator.Request, http.Handler, error) {
	<-etcdReady
	command := app.NewAPIServerCommand(ctx.Done())
	command.SetArgs(args)

	go func() {
		logrus.Fatalf("apiserver exited: %v", command.Execute())
	}()

	startupConfig := <-app.StartupConfig
	return startupConfig.Authenticator, startupConfig.Handler, nil
}

func (Embedded) Scheduler(apiReady <-chan struct{}, args []string) error {
	command := sapp.NewSchedulerCommand()
	command.SetArgs(args)

	go func() {
		<-apiReady
		logrus.Fatalf("scheduler exited: %v", command.Execute())
	}()

	return nil
}
```
