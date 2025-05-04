resource "helm_release" "argocd" {
  name             = "argocd"
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  version          = "7.8.23"
  namespace        = "argocd"
  create_namespace = true
  cleanup_on_fail  = true
  recreate_pods    = true
  replace          = true

  set =[
    {
      name  = "server.service.type"
      value = "ClusterIP" #LoadBalancer #ClusterIP #NodePort
    },
    {
      name  = "server.ingress.enabled"
      value = "false"  # We are using our own ingress.yaml
    },
    {
      name  = "server.ingress.ingressClassName"
      value = "nginx"
    },
    {
      name  = "server.extraArgs[0]"
      value = "--insecure" # remove this block if you want to use http
    },
   
    # {
    #   name  = "server.ingress.annotations.nginx\\.ingress\\.kubernetes\\.io/backend-protocol"
    #   value = "HTTPS"
    # },
    # {
    #   name  = "server.ingress.annotations.nginx\\.ingress\\.kubernetes\\.io/rewrite-target"
    #   value = "/"
    # },
    # {
    #   name  = "server.ingress.annotations.nginx\\.ingress\\.kubernetes\\.io/ssl-redirect"
    #   value = "false"
    # },
  ]
  depends_on = [helm_release.nginx_ingress]
}