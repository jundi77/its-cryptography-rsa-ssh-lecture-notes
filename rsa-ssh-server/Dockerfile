FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y openssh-server sudo && \
    mkdir /var/run/sshd

# Buat user baru untuk SSH login
RUN useradd -ms /bin/bash student && \
    echo "student ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Buat folder SSH
RUN mkdir /home/student/.ssh && \
    chown student:student /home/student/.ssh && \
    chmod 700 /home/student/.ssh

# Copy public key (nanti dari volume bind)
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
