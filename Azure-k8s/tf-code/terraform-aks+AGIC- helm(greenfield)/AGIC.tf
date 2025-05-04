# https://learn.microsoft.com/en-us/azure/application-gateway/ingress-controller-install-new
# github.io/Azure/application-gateway-ingress-controller/blob/master/docs/setup/install.mod

#---------------------------------------------------
# The jsonencode() function converts a map to a JSON string, and jsondecode() then converts that JSON string back into a map.
locals{
    parameters = jsonencode({
        "clientId": "${module.service_principal.client_id}",
        "clientSecret": "${module.service_principal.client_secret}",
        "tenantId": "${module.service_principal.service_principal_tenant_id}",
        "subscriptionId": "${var.SUB_ID}",
        "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
	      "resourceManagerEndpointUrl": "https://management.azure.com/",
        "activeDirectoryGraphResourceId": "https://graph.windows.net/", 
        "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
        "galleryEndpointUrl": "https://gallery.azure.com/",    
        "managementEndpointUrl": "https://management.core.windows.net/"
    })
}

resource "helm_release" "AGIC" {
  name       = "application-gateway-ingress-controller"
  repository = "https://myexpsa.blob.core.windows.net/mytestcontainer"
  chart      = "ingress-azure"
  version    = "1.8.0" 
  # namespace  = "default" 
  cleanup_on_fail  = true
  recreate_pods    = true
  replace          = true

  set =[
    {
    name  = "verbosityLevel"
    value = "3"
    },
    {
      name  = "appgw.subscriptionId"
      value = "${var.SUB_ID}"
    },
    {
      name  = "appgw.resourceGroup"
      value = "${var.rgname}"
    },
    {
      name  = "appgw.name"
      value = "${module.appgw.appgw_name}"
    },
    {
      name  = "appgw.shared"
      value = "false"
    },
    {
      name  = "armAuth.type"
      value = "servicePrincipal"
    },
    {
      name  = "armAuth.secretJSON"
      value = base64encode(local.parameters) # Pass the entire JSON-encoded string
    },
    {
      name  = "rbac.enabled"
      value = "true"
    },
    {
      name  = "appgw.usePrivateIP"
      value = "false"
    },
    {
      name  = "ingressClassResource.enabled"
      value = "true"
    },
    {
      name  = "ingressClassResource.name"
      value = "azure-application-gateway"
    },
    {
      name  = "ingressClassResource.controllerValue"
      value = "azure-application-gateway"
    },
    {
      name  = "watchNamespace"
      value = "" # or specific namespace if you prefer
    }    
  ]
  depends_on = [ module.appgw,module.aks]
}