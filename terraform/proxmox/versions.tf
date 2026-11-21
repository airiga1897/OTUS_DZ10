terraform {
  required_version = "= 1.13.5"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "= 0.84.1"
    }
  }
  backend "local" {}
}

provider "proxmox" {
  endpoint = var.endpoint
  insecure = true
  # Educational lab: native PVE certificate, verification explicitly disabled.
  # API token comes from PROXMOX_VE_API_TOKEN.
}
