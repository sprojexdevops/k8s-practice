resource "helm_release" "argocd" {
  name             = "argocd"
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  version          = "7.8.7"
  namespace        = "argocd"
  create_namespace = true
  cleanup_on_fail  = true
  recreate_pods    = true
  replace          = true

  set {
    name  = "server.service.type"
    value = "LoadBalancer" #LoadBalancer #ClusterIP #NodePort
  }
  set {
    name  = "server.ingress.enabled"
    value = "false"
  }
  set {
    name  = "server.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-internal"
    value = "false"
  }

  # {
  #   name  = "server.ingress.hosts[0]"
  #   value = "your-domain.com" # Replace with your actual domain
  # },
  # {
  #   name  = "server.ingress.annotations[external-dns.alpha.kubernetes.io/hostname]"
  #   value = "your-domain.com" # Replace with your actual domain
  # }
  depends_on = [helm_release.AGIC]
}