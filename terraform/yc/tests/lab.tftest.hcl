mock_provider "yandex" {}

variables {
  cloud_id      = "synthetic-cloud"
  folder_id     = "synthetic-folder"
  zone          = "ru-central1-d"
  namespace     = "otus-dz10"
  platform_id   = "standard-v3"
  network_cidr  = "10.110.0.0/24"
  admin_cidrs   = ["8.8.8.8/32"]
  cloud_init    = "#cloud-config\n{}"
  function_zip  = "synthetic.zip"
  function_hash = "synthetic"
  host = {
    name     = "dz10-pve", cores = 4, memory_gib = 8, boot_gib = 30,
    data_gib = 20, disk_type = "network-hdd", image_id = "synthetic-image"
  }
}

run "host_parameters" {
  command = plan
  assert {
    condition     = yandex_compute_instance.proxmox.resources[0].cores == 4 && yandex_compute_instance.proxmox.resources[0].memory == 8
    error_message = "Wrong host CPU or RAM"
  }
  assert {
    condition     = yandex_compute_disk.boot.size == 30 && yandex_compute_disk.guests.size == 20 && yandex_compute_disk.boot.type == "network-hdd" && yandex_compute_disk.guests.type == "network-hdd"
    error_message = "Wrong disk sizes or storage class"
  }
  assert {
    condition     = alltrue([for rule in yandex_vpc_security_group.admin.ingress : toset(rule.v4_cidr_blocks) == toset(["8.8.8.8/32"])])
    error_message = "Administrative ingress must be limited to explicit /32"
  }
}

run "reject_wide_ingress" {
  command = plan
  variables {
    admin_cidrs = ["0.0.0.0/0"]
  }
  expect_failures = [var.admin_cidrs]
}
