variable "location" {
  type = string
  description = "The location of the resource group"
  # default = "eastus"
}
variable "resource_group_name" {
  type = string
  description = "The name of the resource group"
  # default = "ForAKS"
}

variable "kubernetes_version" {
  type = string
  description = "The Kubernetes version to use for the AKS cluster"
  # default = ""
}

variable "aks_name" {
  type = string
  description = "The name of the AKS cluster"
}
variable "node_pool_name" {
  type = string
  description = "The name of the node pool"
}

variable "service_principal_name" {
    type = string
}

variable "client_id" {}
variable "client_secret" {
  type = string
  sensitive = true
}
variable "nodepoolsubnet"{}
# variable "appgw_id" {
#   type = string
#   description = "The ID of the Application Gateway"
# }