variable "keyvault_name" {
  type = string
  description = "The name of the keyvault"
  # default = "myspkeyvault"
}

variable "location" {
  type = string
  description = "The location of the keyvault"
  # default = "eastus"
}

variable "resource_group_name" {
  type = string
  description = "The name of the resource group"
  # default = "ForAKS" 
}

variable "service_principal_name" {
    type = string
}

variable "service_principal_object_id" {}
variable "service_principal_tenant_id" {}