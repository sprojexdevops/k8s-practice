variable "appgw_subnet_id" {
  type = string
  description = "The ID of the subnet where the Application Gateway is deployed"
}

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

variable "vnet_name" {
  type = string
  description = "The name of the virtual network"
}