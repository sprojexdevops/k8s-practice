variable "vnet_name" {
  type = string
  description = "The name of the virtual network"
  # default = "aksVirtualNetwork"
}

variable "virtual_network_address_prefix" {
  type        = list(string)
  description = "VNET address prefix."
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

variable "aks_subnets_cidr" {
  type = list(string)
  # default = ["10.0.1.0/24", "10.0.1.0/28"] # It's recommended to use a subnet with a minimum size of /28 /27 /26 for app-gw
}

variable "aks_subnet_names" {
  type = list(string)
  # default = ["aksSubnet", "applicationGatewaySubnet"]
}