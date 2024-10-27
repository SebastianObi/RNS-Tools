#!/bin/bash


if [[ $EUID -ne 0 ]]; then
  echo -e "Error: You need to run this script as root (UID=0)"
  exit 1
fi

if [ -p /dev/stdin ]; then
  echo -e "Error: This script can't be piped!"
  exit 1
fi


# Debian-based systems (e.g., Ubuntu)
if command -v apt &> /dev/null; then
    apt autoremove -y
    apt clean
    exit 0
fi

# Red Hat-based systems (e.g., CentOS, Fedora)
if command -v dnf &> /dev/null; then
    dnf autoremove -y
    dnf clean all
    exit 0
fi

# Arch Linux
if command -v pacman &> /dev/null; then
    pacman -Rns $(pacman -Qdtq) --noconfirm
    pacman -Sc --noconfirm
    exit 0
fi

# SUSE-based systems
if command -v zypper &> /dev/null; then
    zypper remove --clean-deps $(rpm -qa --qf "%{name}\n") -y
    zypper clean --all
    exit 0
fi

# Generic (works on some distributions)
if command -v yum &> /dev/null; then
    yum autoremove -y
    yum clean all
    exit 0
fi


exit 1