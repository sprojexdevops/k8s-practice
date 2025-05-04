terraform {
    backend "azurerm" {
    resource_group_name  = "mytestrg"
    storage_account_name = "myexpsa"
    container_name       = "mytestcontainer"
    key                  = "test.terraform.tfstate"
  }
}