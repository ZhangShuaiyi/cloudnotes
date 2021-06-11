[TOC]

# 证书

## 名词介绍

### 协议
+ ssl: ssl 3.0协议1995年发布，目前已经不安全，主流浏览器已经停止对ssl 3.0的支持。
+ tls: tls 1.3协议2018年发布，现在主流使用tls 1.2和tls 1.3

### 格式标准
+ X.509 为一种公钥证书的格式标准，证书组成结构标准用ASN.1（一种标准的语言）来进行描述. X.509 v3 数字证书结构如下：
```
    证书
        版本号
        序列号
        签名算法
        颁发者
        证书有效期
            此日期前无效
            此日期后无效
        主题
        主题公钥信息
            公钥算法
            主题公钥
        颁发者唯一身份信息（可选项）
        主题唯一身份信息（可选项）
        扩展信息（可选项）
            ...
    证书签名算法
    数字签名
```

### 编码格式
同样的X.509证书,可能有不同的编码格式,目前有以下两种编码格式
+ PEM(Privacy Enhanced Mail) 为ASCII文本格式，PEM是一种事实上的标准文件格式，采用base64来编码密钥或证书等其他二进制数据，以便在仅支持ASCII文本的环境中使用二进制数据。具体格式如下
    ```
    -----BEGIN <label name>-----
    base64 string...
    -----END <label name>-----
    -----BEGIN <label name>-----
    base64 string...
    -----END <label name>-----
    ```
    一个文件中可以有1~N个label，常用的label有
    + CERTIFICATE : 公钥证书文件
    + CERTIFICATE REQUEST : CSR请求证书文件
    + PRIVATE KEY : 私钥文件
    + PUBLIC KEY : 公钥文件
    + X509 CRL : X509证书吊销列表文件
    + **扩展名可以为.pem .cer crt .key**，根据文件中label名称确定具体类型
    + 查看X.509格式证书 **openssl x509 -in <证书文件名称> -text -noout**
    + 查看rsa密钥信息 **openssl rsa -in <密钥文件名称> -text -noout**
+ DER(Distinguished Encoding Rules) 是一种二进制编码格式，Windows中常使用这种格式。
    + 查看证书信息 **openssl x509 -in <证书文件名称> -inform der -text -noout**
    + 查看密钥信息 **openssl rsa -in <密钥文件名称> -text -noout -inform der**

### 文件扩展名
+ crt 为证书文件，常见于linux系统，有可能是PEM编码，也有可能是DER编码，大多数应该是PEM编码。
+ cer 为证书文件，常见于Windows系统，可能是PEM编码，也可能是DER编码，大多数应该是DER编码。
+ key 通常用来存放公钥或私钥，编码可以是PEM或DER
    + 查看PEM编码的rsa密钥信息 **openssl rsa -in <密钥文件名称> -text -noout**
    + 查看DER密码的rsa密钥信息 **openssl rsa -in <密钥文件名称> -text -noout -inform der**
+ csr(Certificate Signing Request) 证书签名请求，这个并不是证书，而是向权威证书颁发机构获得签名证书的申请，其核心内容是一个公钥(当然还附带了一些别的信息)，在生成这个申请的时候，同时也会生成一个私钥，私钥要自己保管好。
    + 查看CSR信息**openssl req -noout -text -in <csr文件名称>**
    + 创建CSR文件domain.csr，并同时创建私钥文件domain.key
    ```
    openssl req -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr
    ```
    + 从现有的crt和key可以重新获取csr信息，以k8s的apiserver.crt和apiserver.key为例获取apiserver.csr
    ```
    openssl x509 -in /etc/kubernetes/pki/apiserver.crt -signkey /etc/kubernetes/pki/apiserver.key -x509toreq -out apiserver.csr
    ```

## openssl命令

### openssl x509
在K8s中ca.crt为根证书保存在/etc/kubernetes/pki/ca.crt，在K3s中有两个根证书分别是client-ca.crt和server-ca.crt，保存在
```sh
8d5a0475833112e0bf1ab4ed32052afc  /var/lib/rancher/k3s/agent/client-ca.crt
471ece9546dfab4a3e195c3ac1c9c252  /var/lib/rancher/k3s/agent/server-ca.crt
8d5a0475833112e0bf1ab4ed32052afc  /var/lib/rancher/k3s/server/tls/client-ca.crt
471ece9546dfab4a3e195c3ac1c9c252  /var/lib/rancher/k3s/server/tls/server-ca.crt
```
通过openssl命令可查看证书内容
/var/lib/rancher/k3s/server/tls/client-ca.crt信息
```sh-session
[root@shyi-test-1 ~]# openssl x509 -text -noout -in /var/lib/rancher/k3s/server/tls/client-ca.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0 (0x0)
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=k3s-client-ca@1622699585
        Validity
            Not Before: Jun  3 05:53:05 2021 GMT
            Not After : Jun  1 05:53:05 2031 GMT
        Subject: CN=k3s-client-ca@1622699585
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:39:67:de:ed:f5:b2:69:f9:63:49:7c:99:c7:cc:
                    7b:ed:4f:cb:de:0f:6c:77:1a:f1:25:3e:24:92:f6:
                    a7:fb:2b:73:90:46:81:0a:2b:b1:26:f1:8b:06:1a:
                    c1:66:31:26:92:1b:81:9d:18:83:0e:6e:c0:6a:78:
                    9d:69:b9:96:5a
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Certificate Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                78:B0:C0:41:17:76:F9:36:C3:B3:9C:63:FE:C5:40:CD:82:00:B0:37
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:a5:13:99:ee:13:83:60:1b:90:93:da:1a:3f:
         87:c8:ec:92:9c:48:e5:3a:2c:5b:e6:c7:95:e2:e3:26:15:fd:
         14:02:21:00:8e:6c:15:0d:82:dd:68:d6:02:c0:25:13:68:79:
         62:bf:1c:ef:66:f8:e2:90:c6:e5:5e:ed:90:33:03:b4:81:c6
```
+ 颁发者CN(Common Name)为k3s-client-ca@1622699585
+ 使用者CN(Common Name)为k3s-client-ca@1622699585
+ 有效期10年

/var/lib/rancher/k3s/server/tls/server-ca.crt信息
```sh-session
[root@shyi-test-1 ~]# openssl x509 -text -noout -in /var/lib/rancher/k3s/server/tls/server-ca.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0 (0x0)
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=k3s-server-ca@1622699585
        Validity
            Not Before: Jun  3 05:53:05 2021 GMT
            Not After : Jun  1 05:53:05 2031 GMT
        Subject: CN=k3s-server-ca@1622699585
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:ab:84:03:eb:95:a6:86:50:4e:aa:f3:17:bd:4c:
                    21:e2:d3:ba:c9:46:fe:a1:6a:f2:47:34:1e:d2:34:
                    2f:f5:83:a9:97:72:13:d4:3f:b4:11:8b:c0:51:9b:
                    91:87:c0:71:53:27:54:8d:c9:02:56:46:83:61:c3:
                    ec:f0:86:ec:f6
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Certificate Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                00:66:35:AC:49:40:3F:1A:52:A6:BF:DB:8E:31:BE:B1:1A:82:94:8E
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:d5:14:6b:8f:29:9c:ab:0f:0c:3f:94:34:36:
         65:a8:20:d9:42:8f:cd:89:25:45:e8:6d:0c:5f:1f:c3:59:2f:
         25:02:21:00:93:eb:aa:de:fe:bf:d6:08:7c:de:d1:88:87:7f:
         66:b6:e8:e2:12:88:7c:1e:f0:9a:38:ec:59:19:b1:63:8a:65
```
+ 颁发者CN(Common Name)为k3s-server-ca@1622699585
+ 使用者CN(Common Name)为k3s-server-ca@1622699585
+ 有效期10年

### openssl verify
kubeconfig中的证书信息获取如下
```sh
kubectl config view --raw -o jsonpath='{.users[0].user.client-certificate-data}' | base64 -d > admin.crt
kubectl config view --raw -o jsonpath='{.users[0].user.client-key-data}' | base64 -d > admin.key
kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > ca.crt
```
+ ca.crt和/var/lib/rancher/k3s/server/tls/server-ca.crt相同
    ```sh-session
    [root@shyi-test-1 ca]# md5sum ca.crt /var/lib/rancher/k3s/server/tls/server-ca.crt
    471ece9546dfab4a3e195c3ac1c9c252  ca.crt
    471ece9546dfab4a3e195c3ac1c9c252  /var/lib/rancher/k3s/server/tls/server-ca.crt
    ```
+ admin.crt由/var/lib/rancher/k3s/server/tls/client-ca.crt颁发
    ```sh-session
    [root@shyi-test-1 ca]# openssl verify -CAfile /var/lib/rancher/k3s/server/tls/client-ca.crt admin.crt
    admin.crt: OK
    ```
K3s中其它证书颁发情况: 
client-ca.crt颁发的证书
```
/var/lib/rancher/k3s/server/tls/client-admin.crt
/var/lib/rancher/k3s/server/tls/client-cloud-controller.crt
/var/lib/rancher/k3s/server/tls/client-controller.crt
/var/lib/rancher/k3s/server/tls/client-k3s-controller.crt
/var/lib/rancher/k3s/server/tls/client-kube-apiserver.crt
/var/lib/rancher/k3s/server/tls/client-kube-proxy.crt
/var/lib/rancher/k3s/server/tls/client-scheduler.crt
/var/lib/rancher/k3s/agent/client-k3s-controller.crt
/var/lib/rancher/k3s/agent/client-kubelet.crt
/var/lib/rancher/k3s/agent/client-kube-proxy.crt
```
server-ca.crt颁发的证书
```
/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt
/var/lib/rancher/k3s/agent/serving-kubelet.crt
```

kube-apiserver通过 **--client-ca-file** 参数指定client-ca.crt
```sh
--client-ca-file=/var/lib/rancher/k3s/server/tls/client-ca.crt
```
kube-apiserver通过 **--tls-cert-file** 参数指定serving-kube-apiserver.crt
```sh-session
[root@shyi-test-1 ca]# openssl verify -CAfile ca.crt /var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt
/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt: OK
```

### openssl s_client
可使用openssl s_client连接K3s环境6443端口验证
```sh
openssl s_client -CAfile ca.crt -connect 127.0.0.1:6443
```
可得到 **Verify return code: 0 (ok)** 结果
可以通过openssl s_server和openssl s_client进行双向认证测试
+ server端
```sh
openssl s_server -accept 1443 -Verify 1 \
    -CAfile /var/lib/rancher/k3s/server/tls/client-ca.crt \
    -cert /var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt \
    -key /var/lib/rancher/k3s/server/tls/serving-kube-apiserver.key
```
+ client端
```sh
openssl s_client -CAfile ca.crt -cert admin.crt -key admin.key -connect 127.0.0.1:1443 -showcerts
```


参考
[公钥与私钥](https://zhuanlan.zhihu.com/p/31477508)
[SSL证书详解和CFSSL工具使用](https://www.cnblogs.com/Serverlessops/p/13490874.html)
[那些证书相关的玩意儿(SSL,X.509,PEM,DER,CRT,CER,KEY,CSR,P12等)](https://www.cnblogs.com/guogangj/p/4118605.html)
[openssl、x509、crt、cer、key、csr、ssl、tls 这些都是什么鬼?](https://www.cnblogs.com/yjmyzz/p/openssl-tutorial.html)
[[信息安全] 05 X.509 公钥证书的格式标准](https://www.cnblogs.com/linianhui/p/security-x509.html)
[What is the difference between .pem, .csr, .key and .crt and other such file extensions?](https://crypto.stackexchange.com/questions/43697/what-is-the-difference-between-pem-csr-key-and-crt-and-other-such-file-ext)
[OpenSSL 精粹：SSL 证书、私钥和 CSR](https://linux.cn/article-12293-1.html)
[SSL/TLS原理详解](https://cloud.tencent.com/developer/article/1115445)
[理解SSL/TLS系列(一) 概述](https://blog.csdn.net/zhanyiwp/article/details/105529056)

[一文带你彻底厘清 Kubernetes 中的证书工作机制](https://zhaohuabing.com/post/2020-05-19-k8s-certificate/)
[使用 kubeadm 进行证书管理](https://kubernetes.io/zh/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/)
[PKI 证书和要求](https://kubernetes.io/zh/docs/setup/best-practices/certificates/)
[证书](https://kubernetes.io/zh/docs/tasks/administer-cluster/certificates/)

# kube-apiserver证书

## DefaultBuildHandlerChain
在DefaultBuildHandlerChain中会初始化http.Handler，为http.Handler添加各种处理，其中包含身份验证的处理
```go
	failedHandler = filterlatency.TrackCompleted(failedHandler)
	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences)
	handler = filterlatency.TrackStarted(handler, "authentication")
```
使用bpftrace查看DefaultBuildHandlerChain函数在K3s启动时的调用栈
```sh-session
[root@shyi-test-1 ~]# cat | BPFTRACE_STRLEN=128 bpftrace - <<EOF
uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:*.DefaultBuildHandlerChain {
    printf("%d %s %s\n", pid, comm, func);
    printf("%s\n", ustack(perf));
}
EOF
...
28987 k3s-server github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/server.DefaultBuildHandlerChain

    1e0f720 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/server.DefaultBuildHandlerChain+0
    1e15265 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/server.NewAPIServerHandler+645
    1e0e029 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/server.completedConfig.New+297
    2d88347 github.com/rancher/k3s/vendor/k8s.io/kube-aggregator/pkg/apiserver.completedConfig.NewWithDelegate+135
    2e99b59 github.com/rancher/k3s/vendor/k8s.io/kubernetes/cmd/kube-apiserver/app.createAggregatorServer+121
    2e9ca98 github.com/rancher/k3s/vendor/k8s.io/kubernetes/cmd/kube-apiserver/app.CreateServerChain+1304
    2e9c497 github.com/rancher/k3s/vendor/k8s.io/kubernetes/cmd/kube-apiserver/app.Run+343
    2ea2bde github.com/rancher/k3s/vendor/k8s.io/kubernetes/cmd/kube-apiserver/app.NewAPIServerCommand.func2+318
    2762a3c github.com/rancher/k3s/vendor/github.com/spf13/cobra.(*Command).execute+1148
    27635b5 github.com/rancher/k3s/vendor/github.com/spf13/cobra.(*Command).ExecuteC+885
    34fcc8f github.com/rancher/k3s/pkg/daemons/executor.Embedded.APIServer.func1+47
    472641 runtime.goexit+1
```

## WithAuthentication
在 **github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/endpoints/filters.WithAuthentication** 函数中注册了验证函数
```go
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authenticationStart := time.Now()

		if len(apiAuds) > 0 {
			req = req.WithContext(authenticator.WithAudiences(req.Context(), apiAuds))
		}
		resp, ok, err := auth.AuthenticateRequest(req)
		defer recordAuthMetrics(resp, ok, err, apiAuds, authenticationStart)
		if err != nil || !ok {
			if err != nil {
				klog.Errorf("Unable to authenticate the request due to an error: %v", err)
			}
			failed.ServeHTTP(w, req)
			return
		}

		if !audiencesAreAcceptable(apiAuds, resp.Audiences) {
			err = fmt.Errorf("unable to match the audience: %v , accepted: %v", resp.Audiences, apiAuds)
			klog.Error(err)
			failed.ServeHTTP(w, req)
			return
		}

		// authorization header is not required anymore in case of a successful authentication.
		req.Header.Del("Authorization")

		req = req.WithContext(genericapirequest.WithUser(req.Context(), resp.User))
		handler.ServeHTTP(w, req)
	})
```

## AuthenticateRequest
在WithAuthentication.func1中调用 **auth.AuthenticateRequest** 进行身份验证，使用bpftrace查看
```sh
cat | BPFTRACE_STRLEN=128 bpftrace - <<EOF
uprobe:/var/lib/rancher/k3s/data/current/bin/containerd:"github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/authentication/request/x509.(*Authenticator).AuthenticateRequest" {
    printf("%d %s %s\n", pid, comm, func);
    printf("%s\n", ustack(perf));
    exit();
}
EOF
...
28987 k3s-server github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/authentication/request/x509.(*Authenticator).AuthenticateRequest

        1b958e0 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/authentication/request/x509.(*Authenticator).AuthenticateRequest+0 
        1b949f5 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/authentication/group.(*AuthenticatedGroupAdder).AuthenticateRequest+85 
        1b9a7c5 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/authentication/request/union.(*unionAuthRequestHandler).AuthenticateRequest+165 
        1b9a7c5 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/authentication/request/union.(*unionAuthRequestHandler).AuthenticateRequest+165 
        1c21526 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/endpoints/filters.WithAuthentication.func1+614 
        8da424 net/http.HandlerFunc.ServeHTTP+68 
        1c1358a github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/endpoints/filterlatency.trackStarted.func1+906 
        8da424 net/http.HandlerFunc.ServeHTTP+68 
        1cf4fca github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/server/filters.(*timeoutHandler).ServeHTTP+1066 
        1cf94b7 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/server/filters.WithWaitGroup.func1+311 
        8da424 net/http.HandlerFunc.ServeHTTP+68 
        1c25bc9 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/endpoints/filters.WithRequestInfo.func1+617 
        8da424 net/http.HandlerFunc.ServeHTTP+68 
        1c26947 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/endpoints/filters.WithWarningRecorder.func1+423 
        8da424 net/http.HandlerFunc.ServeHTTP+68 
        1c22f28 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/endpoints/filters.WithCacheControl.func1+168 
        8da424 net/http.HandlerFunc.ServeHTTP+68 
        1c25787 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/endpoints/filters.withRequestReceivedTimestampWithClock.func1+423 
        8da424 net/http.HandlerFunc.ServeHTTP+68 
        1c168e2 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/server/httplog.WithLogging.func1+802 
        8da424 net/http.HandlerFunc.ServeHTTP+68 
        1cfa2c6 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/server/filters.withPanicRecovery.func1+230 
        8da424 net/http.HandlerFunc.ServeHTTP+68 
        1e16871 github.com/rancher/k3s/vendor/k8s.io/apiserver/pkg/server.(*APIServerHandler).ServeHTTP+81 
        350ee53 github.com/rancher/k3s/vendor/github.com/gorilla/mux.(*Router).ServeHTTP+211 
        350ee53 github.com/rancher/k3s/vendor/github.com/gorilla/mux.(*Router).ServeHTTP+211 
        350ee53 github.com/rancher/k3s/vendor/github.com/gorilla/mux.(*Router).ServeHTTP+211 
        350ee53 github.com/rancher/k3s/vendor/github.com/gorilla/mux.(*Router).ServeHTTP+211 
        36c9684 github.com/rancher/k3s/pkg/cluster.(*Cluster).router.func1+100 
        8da424 net/http.HandlerFunc.ServeHTTP+68 
        36c95f5 github.com/rancher/k3s/pkg/cluster.(*Cluster).getHandler.func1+149 
        8da424 net/http.HandlerFunc.ServeHTTP+68 
        8ddb23 net/http.serverHandler.ServeHTTP+163 
        8d922d net/http.(*conn).serve+2221 
        472641 runtime.goexit+1 
```
