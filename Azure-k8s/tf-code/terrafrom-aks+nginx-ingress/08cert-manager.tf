resource "helm_release" "cert_manager" {
  name       = "cert-manager"
  repository = "https://charts.jetstack.io"
  chart      = "cert-manager"
  version    = "v1.17.2" 
  namespace  = "cert-manager" 
  create_namespace = true
  cleanup_on_fail  = true
  recreate_pods    = true
  replace          = true

  set =[ 
    {
      name  = "crds.enabled"
      value = "true"
    }
  ]
  depends_on = [ module.aks]
}

# Issuer is a resource that represents a certificate authority (CA) that can be used to issue certificates.
# ClusterIssuer is a cluster-scoped version of Issuer, which means it can be used across all namespaces in the cluster.
# Create a ClusterIssuer

resource "kubernetes_manifest" "cert_manager_cluster_issuer" {
  manifest = {
    apiVersion = "cert-manager.io/v1"
    kind      = "ClusterIssuer"
    metadata = {
      name = "letsencrypt-prod"
    }
    spec = {
      acme = {
        server = "https://acme-v02.api.letsencrypt.org/directory"
        email  = var.email
        privateKeySecretRef = {
          name = "letsencrypt-prod-cluster-issuer"
        }
        solvers = [
          {
            http01 = {
              ingress = {
                class = "nginx"
              }
            }
          }
        ]
      }
    }
  }

  depends_on = [module.aks, helm_release.cert_manager]
}

# apiVersion: cert-manager.io/v1
# kind: ClusterIssuer
# metadata:
#   name: letsencrypt-prod
# spec:
#     acme:
#         server: "https://acme-v02.api.letsencrypt.org/directory"
#         email: skanth306@gmail.com
#         privateKeySecretRef:
#             name: letsencrypt-prod-cluster-issuer
#         solvers:
#         - http01:
#             ingress:
#                 class: nginx