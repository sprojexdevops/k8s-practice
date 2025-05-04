resource "helm_release" "nginx_ingress" {
  name       = "nginx-ingress-controller"
  repository = "https://kubernetes.github.io/ingress-nginx"
  chart      = "ingress-nginx"
  version    = "4.7.1" 
  namespace  = "ingress-basic" 
  create_namespace = true
  cleanup_on_fail  = true
  recreate_pods    = true
  replace          = true

  set =[ 
    {
      name  = "controller.replicaCount"
      value = "2"
    },
    {
      name  = "controller.nodeSelector"
      map = {
        "kubernetes.io/os" = "linux"
      }
    },
    {
      name  = "defaultBackend.nodeSelector"
      map = {
        "kubernetes.io/os" = "linux"
      }
    },
    {
      name  = "controller.service.externalTrafficPolicy"
      value = "Local"
    }
  ]
  depends_on = [ module.aks]
}