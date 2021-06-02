# ceph配置

## 创建pool
```
ceph osd pool create k3s 128
ceph osd pool set k3s size 1
```

## 创建用户
```
ceph auth get-or-create client.k3s mon 'profile rbd' osd 'profile rbd pool=k3s' mgr 'profile rbd pool=k3s'
```

# ceph-csi
使用v3.3.1进行验证

## 下载镜像
从国内源下载k8s.gcr.io/sig-storage镜像
```
src_registry="registry.aliyuncs.com/it00021hot"
images=(
  csi-provisioner:v2.0.4
  csi-snapshotter:v4.0.0
  csi-attacher:v3.0.2
  csi-resizer:v1.0.1
  csi-node-driver-registrar:v2.0.1
)

for img in ${images[@]};
do
  k3s ctr images pull ${src_registry}/$img
  k3s ctr images tag  ${src_registry}/$img k8s.gcr.io/sig-storage/$img
  k3s ctr images rm ${src_registry}/$img
done
```

## deploy
进入ceph-csi源码的deploy/rbd/kubernetes/目录
```
kubectl create -f csi-provisioner-rbac.yaml
kubectl create -f csi-nodeplugin-rbac.yaml
kubectl create -f csi-provisioner-psp.yaml
kubectl create -f csi-nodeplugin-psp.yaml
```
配置csi-config-map.yaml，在ceph monitor节点执行"ceph mon dump"查看ceph集群信息
```
[root@storage-test-2 /]# ceph mon dump
dumped monmap epoch 1
epoch 1
fsid 02bfd04d-8adb-443b-998e-bc172ec5515b
last_changed 2021-05-06 05:37:11.934158
created 2021-05-06 05:37:11.934158
min_mon_release 14 (nautilus)
0: [v2:192.168.1.72:3300/0,v1:192.168.1.72:6789/0] mon.storage-test-2
```
修改csi-config-map.yaml
```
---
apiVersion: v1
kind: ConfigMap
data:
  config.json: |-
    [
      {
        "clusterID": "02bfd04d-8adb-443b-998e-bc172ec5515b",
        "monitors": ["192.168.1.72:6789"]
      }
    ]
metadata:
  name: ceph-csi-config
```
创建configmap
```
kubectl create -f csi-config-map.yaml
```
注释掉csi-rbdplugin-provisioner.yaml和csi-rbdplugin.yaml相关的内容，并修改csi-rbdplugin-provisioner.yaml中的replicas数目
```
kubectl create -f csi-rbdplugin-provisioner.yaml
kubectl create -f csi-rbdplugin.yaml
```

## example
进入ceph-csi源码的examples/rbd目录

### secret.yaml
修改secret.yaml内容，首先查看ceph k3s用户的认证信息
```
[root@storage-test-2 /]# ceph auth get client.k3s
exported keyring for client.k3s
[client.k3s]
        key = AQAitpNgei5BLRAAnCTUeKiIHECxZx5r51/eNw==
        caps mgr = "profile rbd pool=k3s"
        caps mon = "profile rbd"
        caps osd = "profile rbd pool=k3s"
```
修改secret.yaml为
```
---
apiVersion: v1
kind: Secret
metadata:
  name: csi-rbd-secret
  namespace: default
stringData:
  # Key values correspond to a user name and its key, as defined in the
  # ceph cluster. User ID should have required access to the 'pool'
  # specified in the storage class
  userID: k3s
  userKey: AQAitpNgei5BLRAAnCTUeKiIHECxZx5r51/eNw==
```
创建Secret 
```
kubectl apply -f secret.yaml
```

### storageclass.yaml
修改storageclass.yaml
```
-   clusterID: <cluster-id>
+   clusterID: 02bfd04d-8adb-443b-998e-bc172ec5515b

    # (optional) If you want to use erasure coded pool with RBD, you need to
    # create two pools. one erasure coded and one replicated.
@@ -27,7 +27,7 @@ parameters:

    # (required) Ceph pool into which the RBD image shall be created
    # eg: pool: rbdpool
-   pool: <rbd-pool-name>
+   pool: k3s
```
创建StorageClass
```
kubectl apply -f storageclass.yaml
```

### pvc.yaml
pvc.yaml不用修改，内容为
```
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: rbd-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  storageClassName: csi-rbd-sc
```
创建pvc
```
kubectl apply -f pvc.yaml
```
使用kubectl get pvc和get pv进行查看
```
[root@shyi-1 rbd]# kubectl get pvc
NAME      STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
rbd-pvc   Bound    pvc-680f0ce2-b6de-425f-a961-4a210e11dc0d   1Gi        RWO            csi-rbd-sc     83s
[root@shyi-1 rbd]# kubectl get pv
NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM             STORAGECLASS   REASON   AGE
pvc-680f0ce2-b6de-425f-a961-4a210e11dc0d   1Gi        RWO            Delete           Bound    default/rbd-pvc   csi-rbd-sc              85s
```
此时在ceph节点查看k3s pool信息
```
[root@storage-test-2 /]# rbd ls -p k3s
csi-vol-28836d12-ae50-11eb-af19-be97d761c7ae
```

### pod.yaml
pod.yaml不用修改，内容为
```
---
apiVersion: v1
kind: Pod
metadata:
  name: csi-rbd-demo-pod
spec:
  containers:
    - name: web-server
      image: docker.io/library/nginx:latest
      volumeMounts:
        - name: mypvc
          mountPath: /var/lib/www/html
  volumes:
    - name: mypvc
      persistentVolumeClaim:
        claimName: rbd-pvc
        readOnly: false
```
创建pod
```
kubectl apply -f pod.yaml
```

### 查看rbd信息
在节点上通过lsblk可查看到/dev/rbd0块设备
```
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
rbd0   251:0    0    1G  0 disk /var/lib/kubelet/pods/0c66202d-7554-48dc-900d-32a50e77768a/volumes/kubernetes.io~csi/pvc-680f0ce2-b6de-425f-a961-4a210e11dc0d/mount
```
使用"rbd showmapped"查看rbd挂载信息
```
[root@shyi-1 rbd]# kubectl exec csi-rbdplugin-jgrh2 -c csi-rbdplugin -i -t -- rbd showmapped
id  pool  namespace  image                                         snap  device
0   k3s              csi-vol-28836d12-ae50-11eb-af19-be97d761c7ae  -     /dev/rbd0
```
在csi-rbd-demo-pod中查看到rbd0的使用
```
[root@shyi-1 rbd]# kubectl exec -it csi-rbd-demo-pod -- lsblk -l
NAME MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
rbd0 251:0    0    1G  0 disk /var/lib/www/html
vda  252:0    0  100G  0 disk
vda1 252:1    0  100G  0 part /etc/resolv.conf
```
