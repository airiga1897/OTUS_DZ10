terraform {
  required_version = "= 1.13.5"
  required_providers {
    yandex = {
      source  = "yandex-cloud/yandex"
      version = "= 0.168.0"
    }
  }
  backend "local" {}
}

provider "yandex" {
  cloud_id  = var.cloud_id
  folder_id = var.folder_id
  zone      = var.zone
}
