resource "azurerm_public_ip" "pip" {
  name                = "appgw-pip"
  resource_group_name = var.resource_group_name
  location            = var.location
  allocation_method   = "Static" # Static or Dynamic
  sku                 = "Standard"
  # zones = [1, 2, 3]

  tags = {
    environment = "Production"
  }
}

resource "azurerm_application_gateway" "appgw" {
  name                = "applicationGateway"
  resource_group_name = var.resource_group_name
  location            = var.location
  enable_http2 = false
  # zones = [1, 2, 3]

  sku {
    name     = "Standard_v2" # Basic, WAF_v2, Standard_v2
    tier     = "Standard_v2" 
    capacity = 1
    
  }

  gateway_ip_configuration {
    name      = "appGatewayIpConfig"
    subnet_id = var.appgw_subnet_id
  }

  frontend_port {
    name = local.frontend_port_name
    port = 80
  }

  frontend_ip_configuration {
    name                 = local.frontend_ip_configuration_name
    public_ip_address_id = azurerm_public_ip.pip.id
  }

  backend_address_pool {
    name = local.backend_address_pool_name
  }

  backend_http_settings {
    name                  = local.http_setting_name
    cookie_based_affinity = "Disabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 20
  }

  http_listener {
    name                           = local.listener_name
    frontend_ip_configuration_name = local.frontend_ip_configuration_name
    frontend_port_name             = local.frontend_port_name
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = local.request_routing_rule_name
    priority                   = "100"
    rule_type                  = "Basic" # Basic, PathBasedRouting
    http_listener_name         = local.listener_name
    backend_address_pool_name  = local.backend_address_pool_name
    backend_http_settings_name = local.http_setting_name
  }

  lifecycle {
    ignore_changes = [
       tags,
       backend_address_pool,
       backend_http_settings,
       http_listener,
       probe,
       request_routing_rule,
    ]
  }
}

