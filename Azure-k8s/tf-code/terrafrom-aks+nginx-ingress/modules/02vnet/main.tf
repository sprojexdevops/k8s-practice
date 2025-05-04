resource "azurerm_virtual_network" "aks_vnet" {
  name                = var.vnet_name
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = var.virtual_network_address_prefix

  tags = {
    environment = "Production"
  }
}

resource "azurerm_subnet" "aks_subnet1" {
  count = length(var.aks_subnet_names)
  name                 = var.aks_subnet_names[count.index]
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.aks_vnet.name
  address_prefixes     = [var.aks_subnets_cidr[count.index]]

}