variable "cloud_id" { type = string }
variable "folder_id" { type = string }
variable "zone" { type = string }
variable "namespace" { type = string }
variable "platform_id" { type = string }
variable "host" {
  type = object({ name = string, cores = number, memory_gib = number, boot_gib = number, data_gib = number, disk_type = string, image_id = string })
}
variable "network_cidr" { type = string }
variable "admin_cidrs" {
  type = list(string)
  validation {
    condition     = alltrue([for cidr in var.admin_cidrs : can(cidrhost(cidr, 0)) && endswith(cidr, "/32")])
    error_message = "Administrative access requires individual IPv4 /32 addresses."
  }
}
variable "cloud_init" {
  type      = string
  sensitive = true
}
variable "function_zip" { type = string }
variable "function_hash" { type = string }
