locals {
  labels = { lab = var.namespace, managed_by = "terraform" }
}

# No allUsers/allAuthenticatedUsers binding: invocation requires IAM authorization.
resource "yandex_function" "operator_ip" {
  name              = "${var.namespace}-operator-ip"
  folder_id         = var.folder_id
  labels            = local.labels
  runtime           = "python312"
  entrypoint        = "main.handler"
  memory            = 128
  execution_timeout = "10"
  user_hash         = var.function_hash
  log_options {
    disabled = true
  }
  content {
    zip_filename = var.function_zip
  }
}

resource "yandex_vpc_network" "lab" {
  name      = "${var.namespace}-network"
  folder_id = var.folder_id
  labels    = local.labels
}

resource "yandex_vpc_subnet" "lab" {
  name           = "${var.namespace}-subnet"
  folder_id      = var.folder_id
  zone           = var.zone
  network_id     = yandex_vpc_network.lab.id
  v4_cidr_blocks = [var.network_cidr]
  labels         = local.labels
}

resource "yandex_vpc_security_group" "admin" {
  name       = "${var.namespace}-admin"
  folder_id  = var.folder_id
  network_id = yandex_vpc_network.lab.id
  labels     = local.labels
  dynamic "ingress" {
    for_each = toset([22, 8006])
    content {
      protocol       = "TCP"
      port           = ingress.value
      v4_cidr_blocks = var.admin_cidrs
    }
  }
  egress {
    protocol       = "ANY"
    v4_cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "yandex_compute_disk" "guests" {
  name      = "${var.namespace}-guests"
  folder_id = var.folder_id
  zone      = var.zone
  type      = var.host.disk_type
  size      = var.host.data_gib
  labels    = local.labels
}

resource "yandex_compute_disk" "boot" {
  name      = "${var.namespace}-boot"
  folder_id = var.folder_id
  zone      = var.zone
  type      = var.host.disk_type
  size      = var.host.boot_gib
  image_id  = var.host.image_id
  labels    = local.labels
}

resource "yandex_compute_instance" "proxmox" {
  name        = var.host.name
  hostname    = var.host.name
  folder_id   = var.folder_id
  zone        = var.zone
  platform_id = var.platform_id
  labels      = local.labels
  resources {
    cores         = var.host.cores
    memory        = var.host.memory_gib
    core_fraction = 100
  }
  boot_disk {
    disk_id     = yandex_compute_disk.boot.id
    auto_delete = false
  }
  secondary_disk {
    disk_id     = yandex_compute_disk.guests.id
    device_name = "dz10-guests"
    auto_delete = false
  }
  network_interface {
    subnet_id          = yandex_vpc_subnet.lab.id
    nat                = true
    security_group_ids = [yandex_vpc_security_group.admin.id]
  }
  metadata = {
    user-data          = var.cloud_init
    serial-port-enable = "1"
  }
}
