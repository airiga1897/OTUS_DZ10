variable "endpoint" { type = string }
variable "node_name" { type = string }
variable "guest" {
  type = object({ name = string, vm_id = number, cores = number, memory_mib = number, disk_gib = number, bridge = string, address = string, gateway = string, dns = string, username = string, cpu_type = string, image_url = string, image_sha512 = string })
}
variable "public_key" { type = string }
variable "cloud_init_file" { type = string }
variable "start_guest" {
  type    = bool
  default = true
}

resource "proxmox_virtual_environment_vm" "guest" {
  name            = var.guest.name
  node_name       = var.node_name
  vm_id           = var.guest.vm_id
  description     = "OTUS DZ10: Terraform managed Debian guest (QEMU emulation)"
  tags            = ["otus-dz10", "terraform"]
  started         = var.start_guest
  on_boot         = true
  stop_on_destroy = true
  machine         = "pc"
  bios            = "seabios"
  cpu {
    cores = var.guest.cores
    type  = var.guest.cpu_type
  }
  memory {
    dedicated = var.guest.memory_mib
    floating  = 0
  }
  disk {
    datastore_id = "dz10-guests"
    import_from  = "local:import/dz10-debian13.qcow2"
    interface    = "virtio0"
    size         = var.guest.disk_gib
    file_format  = "qcow2"
  }
  initialization {
    datastore_id      = "dz10-guests"
    user_data_file_id = var.cloud_init_file
    ip_config {
      ipv4 {
        address = var.guest.address
        gateway = var.guest.gateway
      }
    }
    dns {
      servers = [var.guest.dns]
    }
    user_account {
      username = var.guest.username
      keys     = [var.public_key]
    }
  }
  network_device {
    bridge = var.guest.bridge
    model  = "virtio"
  }
  operating_system { type = "l26" }
  serial_device {}
  agent {
    enabled = true
    timeout = "30m"
  }
  timeout_create   = 1800
  timeout_start_vm = 1800
}

output "guest_id" { value = proxmox_virtual_environment_vm.guest.vm_id }
