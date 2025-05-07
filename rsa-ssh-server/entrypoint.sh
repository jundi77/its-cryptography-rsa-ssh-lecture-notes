#!/bin/bash

# Tambahkan public key jika tersedia
if [ -f "/authorized_keys/student.pub" ]; then
    cp /authorized_keys/student.pub /home/student/.ssh/authorized_keys
    chown student:student /home/student/.ssh/authorized_keys
    chmod 600 /home/student/.ssh/authorized_keys
fi

# Nonaktifkan login password
sed -i 's/^#*PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Jalankan SSH server
/usr/sbin/sshd -D
