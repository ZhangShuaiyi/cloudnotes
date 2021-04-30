## k8s命令

source <(kubectl completion bash)

kubectl create deployment shyi-nginx-deploy --image=nginx --dry-run=client --output=yaml | tee nginx-deploy.yaml
kubectl create deployment shyi-nginx-deploy --image=nginx --port=80 --dry-run=client --output=yaml | tee nginx-deploy.yaml
kubectl apply -f nginx-deploy.yaml
kubectl scale deployment.v1.apps/shyi-nginx-deploy --replicas=3
kubectl expose deployment shyi-nginx-deploy --type=NodePort
kubectl get service

## rest api
kubect命令使用-v=6参数可打印http请求信息
```
kubectl get deployments -n kube-system -v=6
```
使用kubectl proxy代理后，可通过curl 127.0.0.1:8001的方式访问k8s api，namespaces为例子https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#list-namespace-v1-core
```
curl http://127.0.0.1:8001/api/v1/namespaces
```
1.13与1.20 api对比
/api/v1/namespaces                                === /api/v1/namespaces
/api/v1/namespaces/{namespace_name}/pods          === /api/v1/namespaces/{namespace}/pods
/api/v1/namespaces/{namespace_name}/deployments   <=> /apis/apps/v1/namespaces/{namespace_name}/deployments
/api/v1/namespaces/{namespace_name}/statefulsets  <=> /apis/apps/v1/namespaces/{namespace_name}/statefulsets
/api/v1/namespaces/{namespace_name}/secretes      === /api/v1/namespaces/{namespace_name}/secrets
/api/v1/namespaces/{namespace_name}/configmaps    === /api/v1/namespaces/{namespace}/configmaps
/api/v1/namespaces/{namespace_name}/cronjobs      <=> /apis/batch/v1beta1/namespaces/{namespace}/cronjobs
/api/v1/namespaces/{namespace_name}/jobs          <=> /apis/batch/v1/namespaces/{namespace}/jobs
/api/v1/namespaces/{namespace_name}/daemonsets    <=> /apis/apps/v1/namespaces/{namespace}/daemonsets    
/api/v1/namespaces/{namespace_name}/replicasets   <=> /apis/apps/v1/namespaces/{namespace}/replicasets
/api/v1/namespaces/{namespace_name}/replicationcontrollers  === /api/v1/namespaces/{namespace}/replicationcontrollers
/api/v1/namespaces/namespaceName}/pods/{PoName}/log?container={items[0].status.containerStatuses[0].name}
  === /api/v1/namespaces/{namespace}/pods/{name}/log
ws://{Websocket的ip}:32080/exec?namespace={namespacesName}&pod=podName}&container={items[0].status.containerStatuses[0].name}&command=sh
  ???
POST https://192.168.1.152:6443/api/v1/namespaces/{namespace}/pods/{pod}/exec?command=%2Fbin%2Fsh&container={container}&stdin=true&stdout=true&tty=true
/api/v1/nodes                                     === /api/v1/nodes

完整参考
+ https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/
+ Use a WebSocket client to exec commands in a Kubernetes pod https://jasonstitt.com/websocket-kubernetes-exec
+ Support kubectl exec/attach using Websocket  https://github.com/kubernetes/kubernetes/issues/89163
+ Websocket实现k8s容器终端 https://opdays.github.io/post/websocket%E5%AE%9E%E7%8E%B0k8s%E5%AE%B9%E5%99%A8%E7%BB%88%E7%AB%AF/
+ 自己动手实现一个kubectl exec  https://vsxen.github.io/2020/06/20/kubectl-exec/
+ Kubernetes exec API串接分析 https://blog.csdn.net/weixin_30815427/article/details/97886311

## 监控

参考
+ Docker监控之Prometheus https://blog.51cto.com/u_14306186/2518059
+ Docker---Prometheus监控 https://www.feiyiblog.com/2020/04/08/Docker-Prometheus%E7%9B%91%E6%8E%A7/
+ Prometheus监控神器-Kubernetes篇（一） https://segmentfault.com/a/1190000023942841
+ https://sysdig.com/blog/kubernetes-monitoring-prometheus/
+ k8s安装Prometheus+Grafana（无坑版） https://www.jianshu.com/p/ac8853927528
+ Kubernetes K8S之kube-prometheus概述与部署 Prometheus的关键特性架构图基本原理服务过程kube-prometheus下载与配置修
 https://cloud.tencent.com/developer/article/1780158
