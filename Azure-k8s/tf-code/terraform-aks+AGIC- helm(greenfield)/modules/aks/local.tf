locals{
  selected_kubernetes_version = var.kubernetes_version == "" ? data.azurerm_kubernetes_service_versions.current.latest_version : var.kubernetes_version
#   is_valid_version = contains(data.azurerm_kubernetes_service_versions.current.valid_versions, local.selected_kubernetes_version)
}

#  dynamic "validation" {
#     for_each = local.is_valid_version ? [] : [1]

#     content {
#       condition     = local.is_valid_version
#       error_message = "The specified Kubernetes version '${local.selected_kubernetes_version}' is not valid."
#     }
#   }