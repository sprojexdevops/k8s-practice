resource "azurerm_public_ip" "example" {
  name                = "vm-pip"
  resource_group_name = var.rgname
  location            = var.location
  allocation_method   = "Static"

  depends_on = [ module.vnet ]
}

resource "azurerm_network_interface" "main" {
  name                = "Bootstrap-nic"
  location            = var.location
  resource_group_name = var.rgname
  ip_configuration {
    name                          = "testconfiguration1"
    subnet_id                     = module.vnet.subnet_ids[0]
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id = azurerm_public_ip.example.id
    
  }
}
resource "azurerm_network_security_group" "example" {
  name                = "Bootstrap-nsg"
  location            = var.location
  resource_group_name = var.rgname

    security_rule {
        name                       = "ssh"
        priority                   = 100
        direction                  = "Inbound"
        access                     = "Allow"
        protocol                   = "Tcp"
        source_port_range          = "*"
        destination_port_range     = "22"
        source_address_prefix      = "*"
        destination_address_prefix = "*"
    }
    security_rule {
        name                       = "http"
        priority                   = 200
        direction                  = "Inbound"
        access                     = "Allow"
        protocol                   = "Tcp"
        source_port_range          = "*"
        destination_port_range     = "80"
        source_address_prefix      = "*"
        destination_address_prefix = "*"
    }
        security_rule {
        name                       = "https"
        priority                   = 300
        direction                  = "Inbound"
        access                     = "Allow"
        protocol                   = "Tcp"
        source_port_range          = "*"
        destination_port_range     = "443"
        source_address_prefix      = "*"
        destination_address_prefix = "*"
    }
    depends_on = [ module.vnet ]
}
resource "azurerm_network_interface_security_group_association" "example" {
  network_interface_id      = azurerm_network_interface.main.id
  network_security_group_id = azurerm_network_security_group.example.id
}
resource "azurerm_virtual_machine" "main" {
  name                  = "Bootstrap-vm"
  location              = var.location
  resource_group_name   = var.rgname
  network_interface_ids = [azurerm_network_interface.main.id]
  vm_size               = "Standard_B2s"
  delete_os_disk_on_termination = true
  delete_data_disks_on_termination = true

  storage_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
  storage_os_disk {
    name              = "myosdisk1"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Standard_LRS"
  }
  os_profile {
    computer_name  = "hostname"
    admin_username = "testadmin"
    admin_password = "Password1234!"
    custom_data = file("bootstrap.sh") # or custom_data = filebase64("bootstrap.sh")
  }
  os_profile_linux_config {
    disable_password_authentication = false
  }
  tags = {
    environment = "staging"
  }

  depends_on = [ 
    azurerm_network_interface.main,
    module.aks,
    module.vnet
   ]
}


resource "null_resource" "aks_connect" {
  connection {
    type = "ssh"
    host = azurerm_public_ip.example.ip_address
    user = "testadmin"
    password = "Password1234!"
  }
  provisioner "remote-exec" {
    inline = [
      "echo '${file("bootstrap.sh")}' > /tmp/bootstrap.sh",
      "chmod +x /tmp/bootstrap.sh",     
      "echo 'az login --service-principal -u ${module.service_principal.client_id} -p ${module.service_principal.client_secret} --tenant ${module.service_principal.service_principal_tenant_id}' >> /tmp/bootstrap.sh",
      "echo 'az aks get-credentials --resource-group ${var.rgname} --name ${var.aks_name}' >> /tmp/bootstrap.sh",
      "sh /tmp/bootstrap.sh"
    ]
  }
  depends_on = [azurerm_virtual_machine.main]
}