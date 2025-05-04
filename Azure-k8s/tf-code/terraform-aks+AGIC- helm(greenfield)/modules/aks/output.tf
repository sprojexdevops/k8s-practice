# output "kube_config" {
#     description = "Kubeconfig file for connecting to AKS cluster"
#     value       = azurerm_kubernetes_cluster.aks_cluster.kube_config_raw
# }

output "kube_config" {
  value = {
    host                   = azurerm_kubernetes_cluster.aks_cluster.kube_config[0].host
    client_certificate     = azurerm_kubernetes_cluster.aks_cluster.kube_config[0].client_certificate
    client_key             = azurerm_kubernetes_cluster.aks_cluster.kube_config[0].client_key
    cluster_ca_certificate = azurerm_kubernetes_cluster.aks_cluster.kube_config[0].cluster_ca_certificate
  }
}
output "kube_config1" {
  value = azurerm_kubernetes_cluster.aks_cluster.kube_config_raw
}

output "client_certificate" {
  value     = azurerm_kubernetes_cluster.aks_cluster.kube_config[0].client_certificate
  sensitive = true
}

output "ssh_private_key" {
	value = tls_private_key.rsa-4096-example.private_key_openssh
  sensitive = true
}

output "aks_id" {
  value = azurerm_kubernetes_cluster.aks_cluster.id
}