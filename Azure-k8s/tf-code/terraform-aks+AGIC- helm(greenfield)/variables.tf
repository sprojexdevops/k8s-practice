variable "SUB_ID" {
  type    = string
}

variable "rgname" {
  type    = string
}

variable "location" {
  type    = string
}

variable "service_principal_name" {
  type    = string
}
variable "node_pool_name" {
  type    = string
}
variable "aks_name" {
  type        = string
  description = "The name of the AKS cluster"
}

variable "keyvault_name" {
  type    = string
}

variable "kubernetes_version" {
  type    = string
  # default = ""
}

variable "vnet_name" {
  type = string
  description = "The name of the virtual network"
}

variable "virtual_network_address_prefix" {
  type        = list(string)
  description = "VNET address prefix."
}

variable "aks_subnets_cidr" {
  type = list(string)
}

variable "aks_subnet_names" {
  type = list(string)

}
# variable "appgw_id" {
#   type = string
#   description = "The ID of the Application Gateway"
# }