output "function_id" { value = yandex_function.operator_ip.id }
output "host" {
  value = {
    id         = yandex_compute_instance.proxmox.id
    public_ip  = yandex_compute_instance.proxmox.network_interface[0].nat_ip_address
    private_ip = yandex_compute_instance.proxmox.network_interface[0].ip_address
    disk_id    = yandex_compute_disk.guests.id
  }
}
