#!/bin/bash


set -e


error_exit() {
  echo "Error: $1" >&2
  exit 1
}


detect_os() {
  if command -v lsb_release >/dev/null 2>&1; then
    distro=$(lsb_release -si)
  elif [ -f /etc/os-release ]; then
    . /etc/os-release
    distro=$ID
  else
    error_exit "Cannot detect operating system."
  fi
  case "$distro" in
    Ubuntu|LinuxMint|linuxmint|Kali)
      echo "Detected supported OS: $distro"
      ;;
    *)
      error_exit "Unsupported OS: $distro. Only Ubuntu and Linux Mint are supported."
      ;;
  esac
}


update_system() {
  echo "Updating package list and upgrading packages..."
  sudo apt-get update -y
  sudo apt-get upgrade -y
  sudo apt-get dist-upgrade -y
  sudo apt-get autoremove -y
  echo "System updated successfully."
}

enable_auto_updates() {
  echo "Installing and configuring automatic security updates..."
  sudo apt-get install -y unattended-upgrades
  sudo dpkg-reconfigure --priority=low unattended-upgrades || true
  sudo bash -c 'cat <<EOF >/etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF'
  echo "Automatic updates enabled."
}


create_backups() {
  echo "Creating backups of /etc and /home..."
  backup_dir="/var/backup"
  sudo mkdir -p "$backup_dir"
  sudo tar czf "$backup_dir/etc-backup-$(date +%F).tar.gz" /etc
  sudo tar czf "$backup_dir/home-backup-$(date +%F).tar.gz" /home || echo "Warning: /home backup may have permission issues or be large."
  echo "Backups created in $backup_dir."
}


configure_password_policy() {
  echo "Configuring password policy in /etc/login.defs..."
  sudo sed -i '/^PASS_MIN_DAYS/s/.*/PASS_MIN_DAYS   7/' /etc/login.defs
  sudo sed -i '/^PASS_MAX_DAYS/s/.*/PASS_MAX_DAYS  60/' /etc/login.defs
  sudo sed -i '/^PASS_WARN_AGE/s/.*/PASS_WARN_AGE   14/' /etc/login.defs
  echo "Password aging configured (min 7 days, max 60 days, warn 14 days)."
  echo "Installing libpam-pwquality for password strength..."
  sudo apt-get install -y libpam-pwquality
  echo "Updating PAM settings for strong passwords..."
  sudo sed -i '/pam_pwquality\.so/s/$/ retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
  if ! grep -q "pam_tally2.so" /etc/pam.d/common-auth; then
    echo "auth    required    pam_tally2.so deny=5 unlock_time=1800 onerr=fail audit" | sudo tee -a /etc/pam.d/common-auth
  fi
  echo "Password policy enforced (min length 12, complexity, lockout after 5 failures)."
}


remove_unauthorized() {
  echo "Removing unauthorized software (e.g., Samba, P2P clients)..."
  sudo apt-get purge -y samba samba-common smbclient || true
  sudo apt-get purge -y transmission-common transmission-cli || true
  sudo apt-get autoremove -y
  echo "Deleting common media files (*.mp3, *.mp4, etc.) from home directories..."
  sudo find /home -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' \) -delete
  echo "Unauthorized files and software removal complete."
}


configure_firewall() {
  echo "Configuring UFW firewall..."
  sudo apt-get install -y ufw
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow 22/tcp  
  sudo ufw --force enable
  echo "UFW enabled (deny incoming, allow outgoing, SSH allowed)."
}


configure_login_screen() {
  echo "Configuring login screen settings..."
  if [ -f /etc/lightdm/lightdm.conf ]; then
    sudo sed -i '/^\[Seat\:\*\]/a allow-guest=false' /etc/lightdm/lightdm.conf
    sudo sed -i '/^autologin-user/s/^/#/' /etc/lightdm/lightdm.conf
  fi
  if [ -f /etc/gdm3/custom.conf ]; then
    sudo sed -i '/^\[daemon\]/a AllowGuest=false' /etc/gdm3/custom.conf
    sudo sed -i '/^AutomaticLoginEnable/s/true/false/' /etc/gdm3/custom.conf
  fi
  echo "Guest login disabled and auto-login turned off."
}


configure_ssh() {
  echo "Securing SSH configuration..."
  ssh_conf="/etc/ssh/sshd_config"
  sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' $ssh_conf
  sudo sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' $ssh_conf
  sudo sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' $ssh_conf
  sudo sed -i 's/^#*StrictModes.*/StrictModes yes/' $ssh_conf
  sudo sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 20/' $ssh_conf
  sudo sed -i 's/^#*Protocol.*/Protocol 2/' $ssh_conf
  sudo systemctl restart sshd || sudo systemctl restart ssh
  echo "SSH hardened (root login disabled, Protocol 2, etc.)."
}


configure_sudoers() {
  echo "Securing /etc/sudoers..."
  sudo sed -i '/NOPASSWD/d' /etc/sudoers
  sudo chown root:root /etc/sudoers
  sudo chmod 440 /etc/sudoers
  echo "/etc/sudoers secured (passwordless sudo removed, permissions set)."
}


configure_sysctl() {
  echo "Applying sysctl network hardening settings..."
  sudo bash -c 'grep -q "^net.ipv4.tcp_syncookies" /etc/sysctl.conf || echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf'
  sudo bash -c 'grep -q "^net.ipv6.conf.all.disable_ipv6" /etc/sysctl.conf || echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf'
  sudo bash -c 'grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf'
  sudo bash -c 'grep -q "^net.ipv4.icmp_echo_ignore_all" /etc/sysctl.conf || echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf'
  sudo bash -c 'grep -q "^nospoof" /etc/host.conf || echo "nospoof on" >> /etc/host.conf'
  sudo sysctl -p
  echo "Sysctl settings applied."
}


secure_root() {
  echo "Securing root account..."
  sudo passwd -l root
  sudo gpasswd -d root sudo || true
  echo "Root account locked and removed from sudo group (if present)."
}


main_menu() {
  detect_os
  while true; do
    echo
    echo "======== CyberPatriot Hardening Menu ========"
    echo "1) Update system and software"
    echo "2) Enable automatic updates"
    echo "3) Create backups (/etc and /home)"
    echo "4) Enforce password policies"
    echo "5) Remove unauthorized files and software"
    echo "6) Configure firewall (UFW)"
    echo "7) Configure login screen (disable guest, auto-login)"
    echo "8) Secure SSH configuration"
    echo "9) Secure sudoers file"
    echo "10) Apply sysctl hardening"
    echo "11) Secure root account"
    echo "0) Exit"
    echo "============================================"
    read -p "Enter your choice [0-11]: " choice
    case "$choice" in
      1) update_system ;;
      2) enable_auto_updates ;;
      3) create_backups ;;
      4) configure_password_policy ;;
      5) remove_unauthorized ;;
      6) configure_firewall ;;
      7) configure_login_screen ;;
      8) configure_ssh ;;
      9) configure_sudoers ;;
      10) configure_sysctl ;;
      11) secure_root ;;
      0) echo "Exiting script."; break ;;
      *) echo "Invalid option. Please select 0-11." ;;
    esac
    read -n 1 -s -r -p "Press any key to continue..."
    echo
  done
}

main_menu
