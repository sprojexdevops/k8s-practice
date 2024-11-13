terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.66.0"
    }
  }

  backend "s3" {
    bucket         = "sprojex-remote-state"
    key            = "k8s-workstation-main"
    region         = "us-east-1"
    dynamodb_table = "tf-state-locking"
  }
}

provider "aws" {
  # Configuration options
  region = "us-east-1"
}