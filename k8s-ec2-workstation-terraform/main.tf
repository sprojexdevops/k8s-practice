# source --> terraform open source modules in github (no URL required for these)

module "k8s_workstation" {
  source = "terraform-aws-modules/ec2-instance/aws"

  ami  = data.aws_ami.ami.id
  name = "k8s-workstation"

  instance_type          = "t3.micro"
  vpc_security_group_ids = ["sg-0a1fb132f1fc1e49d"]
  subnet_id              = "subnet-08b4b98f8c9b97078"

  tags = {
    Name = "k8s-workstation"
    Terraform = "True"
  }
}

resource "null_resource" "k8s_workstation" {
  # Change of instance id requires re-provisioning
  triggers = {
    instance_id = module.k8s_workstation.id
  }

  # Connect to the server remotely and run the script 
  connection {
    host     = module.k8s_workstation.public_ip
    type     = "ssh"
    user     = "ec2-user"
    password = var.pswd
  }

  # Copy the file from local and run inside the remote server
  provisioner "file" {
    source      = "config.sh"
    destination = "/tmp/config.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/config.sh",
      "sudo sh /tmp/config.sh ${var.AWS_ACCESS_KEY_ID} ${AWS_ACCESS_KEY_SECRET} ${AWS_REGION}"
    ]
  }
}