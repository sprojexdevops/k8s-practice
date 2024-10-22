#!/bin/bash

# Install Docker
yum install -y yum-utils
yum-config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl start docker
usermod -aG docker ec2-user

# Install kubectl
curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.29.8/2024-09-11/bin/linux/amd64/kubectl
chmod +x /kubectl
sudo mv kubectl /usr/local/bin/kubectl

# Install eksctl
ARCH=amd64
PLATFORM=$(uname -s)_$ARCH
curl -sLO "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_$PLATFORM.tar.gz"
tar -xzf eksctl_$PLATFORM.tar.gz -C /tmp && rm eksctl_$PLATFORM.tar.gz
sudo mv /tmp/eksctl /usr/local/bin
