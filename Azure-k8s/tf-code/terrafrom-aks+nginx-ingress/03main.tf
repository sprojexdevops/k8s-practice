resource "azurerm_resource_group" "rg1" {
  name     = var.rgname
  location = var.location

}

module "service_principal" {
  source                 = "./modules/01ServicePrincipal"
  service_principal_name = var.service_principal_name

  depends_on = [azurerm_resource_group.rg1]
}

resource "azurerm_role_assignment" "rolespn" {
  scope                = "/subscriptions/${var.SUB_ID}"
  role_definition_name = "Contributor"
  principal_id         = module.service_principal.service_principal_object_id

  depends_on = [module.service_principal]
}

module "keyvault" {
  source                      = "./modules/03Keyvault"
  keyvault_name               = var.keyvault_name
  location                    = var.location
  resource_group_name         = var.rgname
  service_principal_name      = var.service_principal_name
  service_principal_object_id = module.service_principal.service_principal_object_id
  service_principal_tenant_id = module.service_principal.service_principal_tenant_id
  
  depends_on = [
    module.service_principal
  ]
}

resource "azurerm_key_vault_secret" "example" {
  name         = module.service_principal.client_id
  value        = module.service_principal.client_secret
  key_vault_id = module.keyvault.keyvault_id

  depends_on = [ 
    module.keyvault
  ]
}

resource "azurerm_key_vault_secret" "ssh_private_key" {
  name         = "ssh-private-key"
  value = module.aks.ssh_private_key
  key_vault_id = module.keyvault.keyvault_id
  
  depends_on = [ 
    module.keyvault
  ]
}

module "vnet" {
  source  = "./modules/02vnet"
  vnet_name = var.vnet_name
  virtual_network_address_prefix = var.virtual_network_address_prefix
  location = var.location
  resource_group_name = var.rgname
  aks_subnets_cidr = var.aks_subnets_cidr
  aks_subnet_names = var.aks_subnet_names

  depends_on = [ 
    azurerm_resource_group.rg1 
  ]
}

module "aks" {
  source                 = "./modules/04aks"
  location               = var.location
  aks_name               = var.aks_name
  resource_group_name    = var.rgname
  kubernetes_version     = var.kubernetes_version
  service_principal_name = var.service_principal_name
  client_id              = module.service_principal.client_id
  client_secret          = module.service_principal.client_secret
  node_pool_name = var.node_pool_name
  nodepoolsubnet = module.vnet.subnet_ids[1]
  depends_on = [
    azurerm_resource_group.rg1,
    module.service_principal,
    module.keyvault,
    azurerm_key_vault_secret.example,
  ]
}

resource "local_file" "foo" { # write the kubernetes config(kubeconfig) to a local file
  content  = "${module.aks.kube_config1}"
  filename = "./kubeconfig"
  depends_on = [ module.aks ]
}