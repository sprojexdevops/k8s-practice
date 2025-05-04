#!/bin/bash

# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash


#install docker

# sudo apt  install docker.io -y
# sudo chmod 777 /var/run/docker.sock

# Install kubectl
curl -LO https://dl.k8s.io/release/v1.32.0/bin/linux/amd64/kubectl
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
chmod +x kubectl
mkdir -p ~/.local/bin
mv ./kubectl ~/.local/bin/kubectl
kubectl version --client

# helm install

curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
