terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.23.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "3.1.0"
    }
    kubernetes = {
      source = "hashicorp/kubernetes"
      version = "2.36.0"
    }
    helm = {
      source = "hashicorp/helm"
      version = "3.0.0-pre2"
    }
  }
  required_version = ">=1.9.0"

}

provider "azurerm" {
  # Configuration options
  #   resource_provider_registrations = "none" # This is only required when the User, Service Principal, or Identity running Terraform lacks the permissions to register Azure Resource Providers.
  subscription_id = var.SUB_ID
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
      #   recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }

  }
}
provider "azuread" {}

provider "kubernetes" {
  host                   = module.aks.kube_config.0.host
  cluster_ca_certificate = base64decode(module.aks.kube_config.0.cluster_ca_certificate)
  client_key             = base64decode(module.aks.kube_config.0.client_key)
  client_certificate     = base64decode(module.aks.kube_config.0.client_certificate)
  token                  = module.aks.kube_config.0.token
}

provider "helm" {
  kubernetes = {
    host                   = module.aks.kube_config.host
    client_certificate     = base64decode(module.aks.kube_config.client_certificate)
    client_key             = base64decode(module.aks.kube_config.client_key)
    cluster_ca_certificate = base64decode(module.aks.kube_config.cluster_ca_certificate)
  }
}