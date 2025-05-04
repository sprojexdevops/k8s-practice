data "azurerm_kubernetes_service_versions" "current" {
  location        = var.location
  include_preview = false
}

resource "azurerm_user_assigned_identity" "aks" {
  name                = "aks-${var.aks_name}"
  resource_group_name = var.resource_group_name
  location            = var.location
}

resource "azurerm_kubernetes_cluster" "aks_cluster" {
  name                = var.aks_name
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_prefix          = "${var.resource_group_name}-cluster"
  private_cluster_enabled = false
  role_based_access_control_enabled = true
  kubernetes_version  = local.selected_kubernetes_version
  # node_resource_group = "${var.resource_group_name}-nrg" #expecting this "MC_ResourceGroup_ResourceName_Location" format

  sku_tier = "Free" # "Standard", "Premium" Defaults to "Free"
  automatic_upgrade_channel = "stable" # "patch", "rapid", "node-image", "stable" Defaults to "none"
  oidc_issuer_enabled = true # true, false
  workload_identity_enabled = true # true, false

  default_node_pool {
    name       = var.node_pool_name
    vm_size    = "Standard_DS2_v2"
    auto_scaling_enabled = true # true, false
    min_count = 1
    max_count = 3
    # node_count = 2 # The initial number of nodes which should exist in this Node Pool. You should not specify node_count when auto-scaling is enabled.
    os_disk_size_gb = 40
    # temporary_name_for_rotation = "tempnodepool"
    max_pods = 100
    type  = "VirtualMachineScaleSets"
    # zones = [1, 2, 3]
    vnet_subnet_id  = var.nodepoolsubnet
    node_labels = {
      "nodepool-type"    = "system"
      "environment"      = "prod"
      "nodepools"       = "linux"
    }
    tags = {
      "nodepool-type"    = "system"
      "environment"      = "prod"
      "nodepools"       = "linux"
    }
  }
  identity { # one of either identity or service_principal blocks must be specified.
    type = "UserAssigned" # "SystemAssigned", "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks.id] # This is for UserAssigned identity only
  }

  network_profile {
    network_plugin = "azure" #azure, kubenet, none
    load_balancer_sku = "standard"
  }

  linux_profile {
    admin_username = "ubuntu"
    ssh_key {
      key_data = tls_private_key.rsa-4096-example.public_key_openssh
    }
  }
  lifecycle {
    ignore_changes = [ default_node_pool[0].node_count ]
  }

}

resource "tls_private_key" "rsa-4096-example" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# For Spot nodes

resource "azurerm_kubernetes_cluster_node_pool" "spot_node_pool" {
  name                  = "spotnodepool"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.aks_cluster.id
  vm_size               = "Standard_DS2_v2"
  vnet_subnet_id  = var.nodepoolsubnet
  orchestrator_version = local.selected_kubernetes_version
  priority = "Spot" # "Regular", "Spot"
  spot_max_price = -1
  eviction_policy = "Delete" # "Delete", "Deallocate"

  auto_scaling_enabled = true # true, false
  node_count            = 1
  min_count             = 1
  max_count             = 3

  node_labels = {
    role                                    = "spot"
    "kubernetes.azure.com/scalesetpriority" = "spot"
  
  }
  node_taints = [
    "spot:NoSchedule",
    "kubernetes.azure.com/scalesetpriority=spot:NoSchedule"
  ]

  tags = {
    Environment = "Production"
  }

  lifecycle {
    ignore_changes = [ node_count ]
  }
}