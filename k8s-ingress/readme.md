# Ingress Controller

### reference doc for aws ingress controller
```
https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/
```

### Ingress controller is outside of k8s cluster, so create an IAM service to give access to cluster to manage it
```
eksctl utils associate-iam-oidc-provider \
    --region <xxxxxx> \
    --cluster <cluster name> \
    --approve
```

```
curl -o iam-policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.10.0/docs/install/iam_policy.json
```

```
aws iam create-policy \
    --policy-name AWSLoadBalancerControllerIAMPolicy \
    --policy-document file://iam-policy.json
```

```
eksctl create iamserviceaccount \
--cluster=<cluster name> \
--namespace=kube-system \
--name=aws-load-balancer-controller \
--attach-policy-arn=arn:aws:iam::<account id>:policy/AWSLoadBalancerControllerIAMPolicy \
--override-existing-serviceaccounts \
--region <xxxxxxxx> \
--approve
```

```
helm repo add eks https://aws.github.io/eks-charts
```

```
helm install aws-load-balancer-controller eks/aws-load-balancer-controller -n kube-system --set clusterName=<cluster-name> --set serviceAccount.create=false --set serviceAccount.name=aws-load-balancer-controller
```

```
helm list -n kube-system
```

```
kubectl get pods -n kube-system
```

### if no pods for aws-load-balancer-controller are created, check if it's service account is created

```
kubectl get sa -n kube-system
```

### if no service account is found for aws-load-balancer-controller then uninstall and install helm command by changing --set serviceAccount.create to true

```
helm uninstall aws-load-balancer-controller -n kube-system
```

```
helm install aws-load-balancer-controller eks/aws-load-balancer-controller -n kube-system --set clusterName=<cluster-name> --set serviceAccount.create=true --set serviceAccount.name=aws-load-balancer-controller
```