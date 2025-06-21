module "workstation" {
  source  = "terraform-aws-modules/ec2-instance/aws"

  name = "workstation"

  instance_type          = "t3.micro"
  vpc_security_group_ids = [var.sg_id]
  # convert StringList to list and get first element
  subnet_id = var.public_subnet_id
  ami = data.aws_ami.ami.id
  user_data = file("workstation.sh")
  # after completing, need to run aws configure after login to server
  tags = {
        Name = "workstation"
    }
}