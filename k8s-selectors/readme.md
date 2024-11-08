# Selectors

### Taint the node

```
kubectl taint nodes <node name> <key>=<value>:NoSchedule
```
> eg: kubectl taint nodes ip-192-168-44-187.ec2.internal hardware=gpu:NoSchedule

### Untaint a node with a specific key and value
```
kubectl taint nodes <node name> <key>=<value>:NoSchedule-
```
> eg: kubectl taint nodes ip-192-168-44-187.ec2.internal hardware=gpu:NoSchedule-

### Untaint a node with a specific key
```
kubectl taint nodes <node name> <key>:NoSchedule-
```
> eg: kubectl taint nodes ip-192-168-44-187.ec2.internal hardware:NoSchedule-


### Label a node

```
kubectl label nodes <node name> <key>=<value>
```
> eg: kubectl label nodes ip-192-168-44-187.ec2.internal hardware=gpu

Ref: https://kubernetes.io/docs/tasks/configure-pod-container/assign-pods-nodes
