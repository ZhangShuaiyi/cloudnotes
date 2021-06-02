# 安装

## 脚本安装
执行命令
```
curl -sfL https://get.k3s.io | sh -
```
命令行验证
```
source <(kubectl completion bash)
kubectl create deployment shyi-nginx-deploy --image=nginx --port=80 --dry-run=client --output=yaml | tee nginx-deploy.yaml
kubectl apply -f nginx-deploy.yaml
kubectl get deployments.apps
kubectl get pods
kubectl expose deployment shyi-nginx-deploy --type=NodePort
kubectl get service
```


cat /var/lib/rancher/k3s/server/node-token
./k3s agent --server https://192.168.1.35:6443 --token K100c482850751b2be230fd121e3384dbeb86e3157bb1810efa05eddbcd67f67055::server:0371c8994a1f82ba97a00fbd4d726003

## 离线安装
下载安装脚本
```
curl -sfL https://get.k3s.io > install_k3s.sh
```
准备
```
yum install -y container-selinux selinux-policy-base
yum install -y https://rpm.rancher.io/k3s/stable/common/centos/7/noarch/k3s-selinux-0.2-1.el7_8.noarch.rpm
```
执行安装脚本
```
INSTALL_K3S_SKIP_DOWNLOAD=true INSTALL_K3S_SKIP_ENABLE=true INSTALL_K3S_SKIP_START=true sh install_k3s.sh
```
使用rpm安装etcd并启动etcd服务，k3s配置etcd（暂不配置ca），在/etc/systemd/system/k3s.service.env中添加
```
K3S_DATASTORE_ENDPOINT="http://localhost:2379"
```
通过systemctl start k3s方式启动k3s


参考
附018.K3S-ETCD高可用部署
https://www.cnblogs.com/itzgr/p/12886477.html
基于etcd的k3s高可用部署
https://blog.csdn.net/qingdao666666/article/details/104612119

## 编译
Dockerfile.dapper修改
```
--- a/Dockerfile.dapper
+++ b/Dockerfile.dapper
@@ -24,17 +24,18 @@ RUN if [ "$(go env GOARCH)" = "arm64" ]; then
     mv trivy /usr/local/bin;                                                                                \
     fi
 # this works for both go 1.15 and 1.16
-RUN GO111MODULE=on go get golang.org/x/tools/cmd/goimports@aa82965741a9fecd12b026fbb3d3c6ed3231b8f8
+RUN GO111MODULE=on GOPROXY="https://goproxy.io,direct" go get golang.org/x/tools/cmd/goimports@aa82965741a9fecd12b026fbb3d3c6ed3231b8f8
 RUN rm -rf /go/src /go/pkg

 RUN if [ "$(go env GOARCH)" = "amd64" ]; then \
-    curl -sL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s v1.30.0; \
+    curl -sL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -x -s v1.30.0; \
     fi

 ARG SELINUX=true
 ENV SELINUX $SELINUX

 ENV GO111MODULE off
+ENV GOPROXY https://goproxy.io,direct
 ENV DAPPER_RUN_ARGS --privileged -v k3s-cache:/go/src/github.com/rancher/k3s/.cache -v trivy-cache:/root/.cache/trivy
 ENV DAPPER_ENV REPO TAG DRONE_TAG IMAGE_NAME SKIP_VALIDATE GCLOUD_AUTH GITHUB_TOKEN GOLANG
 ENV DAPPER_SOURCE /go/src/github.com/rancher/k3s/
```
scripts/build修改
```
--- a/scripts/build
+++ b/scripts/build
@@ -33,8 +33,9 @@ VERSIONFLAGS="
     -X ${VENDOR_PREFIX}${PKG_CONTAINERD}/version.Package=${PKG_K3S_CONTAINERD}
     -X ${VENDOR_PREFIX}${PKG_CRICTL}/pkg/version.Version=${VERSION_CRICTL}
 "
-LDFLAGS="
-    -w -s"
+#LDFLAGS="
+#    -w -s"
+LDFLAGS=""
 STATIC="
     -extldflags '-static'
 "
```
scripts/package-cli修改
```
--- a/scripts/package-cli
+++ b/scripts/package-cli
@@ -54,7 +54,6 @@ CMD_NAME=dist/artifacts/k3s${BIN_SUFFIX}
 LDFLAGS="
     -X github.com/rancher/k3s/pkg/version.Version=$VERSION
     -X github.com/rancher/k3s/pkg/version.GitCommit=${COMMIT:0:8}
-    -w -s
 "
 STATIC="-extldflags '-static'"
 CGO_ENABLED=0 "${GO}" build -ldflags "$LDFLAGS $STATIC" -o ${CMD_NAME} ./cmd/k3s/main.go
```

## 打包k3s
在script/package-cli中执行"go generate"，会进一步执行"go run pkg/codegen/main.go"，最终会通过go-bindata库将build/data目录中静态文件打包到pkg/data/zz_generated_bindata.go源码中，"build/data/xxxxxxxxxxxx.tar.zst"为经过tar和zstd打包压缩的./bin和./etc目录。

# 调试

## curl
在server节点使用kubectl proxy代理8080
```
kubectl proxy --port=8080
```
通过curl访问http端口
```
curl http://127.0.0.1:8080/api
curl http://127.0.0.1:8080/
curl http://127.0.0.1:8080/api/v1/pods
```
添加watch参数
```
curl http://127.0.0.1:8080/api/v1/pods?watch=true
```


Tutorial: Install a Highly Available K3s Cluster at the Edge
https://thenewstack.io/tutorial-install-a-highly-available-k3s-cluster-at-the-edge/

参考
从架构到部署，全面了解K3s
http://www.dockone.io/article/10735
轻量级 Kubernetes k3s 初探
https://www.infoq.cn/article/0c7viuflrxozeh7qlrbt
k3s-轻量容器集群，快速入门
https://my.oschina.net/u/2306127/blog/3206994
k3s原理分析丨如何搞定k3s node注册失败问题
http://www.dockone.io/article/9836
Rancher发布K3s
https://www.huaweicloud.com/articles/3a6ff5709238b416f5b7e12b41565b21.html
轻量级Kubernetes之k3s：14:通过token调用REST API
https://blog.csdn.net/liumiaocn/article/details/103393621
使用curl访问k8s的apiserver
https://www.voidking.com/dev-curl-k8s-api-server/
