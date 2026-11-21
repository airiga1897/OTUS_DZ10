mock_provider "proxmox" {}

variables {
  endpoint        = "https://127.0.0.1:8006/"
  node_name       = "dz10-pve"
  public_key      = "synthetic-public-key"
  cloud_init_file = "local:snippets/dz10-guest.yaml"
  start_guest     = false
  guest = {
    name      = "dz10-guest", vm_id = 110, cores = 1, memory_mib = 2048,
    disk_gib  = 10, bridge = "vmbr10", address = "10.111.0.10/24",
    gateway   = "10.111.0.1", dns = "1.1.1.1", username = "student", cpu_type = "qemu64",
    image_url = "https://example.invalid/synthetic.qcow2", image_sha512 = "synthetic"
  }
}

run "create_stopped_before_disabling_kvm" {
  command = plan
  assert {
    condition     = !proxmox_virtual_environment_vm.guest.started && proxmox_virtual_environment_vm.guest.cpu[0].type == "qemu64"
    error_message = "The initial VM must be stopped and use an emulatable CPU"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.guest.disk[0].size == 10 && proxmox_virtual_environment_vm.guest.memory[0].dedicated == 2048
    error_message = "Wrong guest disk or RAM"
  }
}

run "start_guest" {
  command = plan
  variables {
    start_guest = true
  }
  assert {
    condition     = proxmox_virtual_environment_vm.guest.started
    error_message = "Terraform must start the guest in the final phase"
  }
}
