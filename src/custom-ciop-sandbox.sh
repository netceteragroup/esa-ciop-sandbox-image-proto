#!/bin/bash
# Installation script for CIOP demo client
# Copyright (C) 2010-2013  Netcetera Zurich
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
#
# Tested with the following VirtualBox 4.1 configuration
# - GuestOS Type Linux, RedHat
# - 32bit, 512 MB RAM, 5 GB Disk, no audio, nos usb, no floppy in boot order
# - Network:
#     Adapter 1: Intel PRO/1000 MT Desktop (NAT) (port forwarding tcp: host 3333 -> guest 22)
#     Adapter 2: Intel PRO/1000 MT Desktop (internal network, 'g-pod')
#
# Sientific Linux 6.1 i386 installation
# - boot form install DVD
# - start "Install system with basic video driver"
# - Parameters: language English, keyboard sg, timezone Europe/Zurich,
#               root password secret, automatic filesystem layout, dhcp for eth0

# network configuration
cat <<EOF> /etc/sysconfig/network-scripts/ifcfg-eth1
DEVICE="eth1"
BOOTPROTO="none"
NM_CONTROLLED="no"
ONBOOT="yes"
IPADDR=192.168.11.20
NETMASK=255.255.255.0
TYPE=Ethernet
EOF
cat <<EOF> /etc/sysconfig/network
NETWORKING=yes
HOSTNAME=client.g-pod
EOF

# local firewall rules for inbound traffic
lokkit --nostart --enabled --service=ssh

# enable EPEL repository for additional packages
yum install -y epel-release.noarch

# disable auto updates and selinux
sed -i 's/ENABLED="true"/ENABLED="false"/' /etc/sysconfig/yum-autoupdate
sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config

# nfs/autofs Configuration
yum install -y \
  nfs-utils \
  autofs

cat <<EOF>> /etc/sysconfig/autofs
DEFAULT_MAP_OBJECT_CLASS="automountMap"
DEFAULT_ENTRY_OBJECT_CLASS="automount"
DEFAULT_MAP_ATTRIBUTE="ou"
DEFAULT_ENTRY_ATTRIBUTE="cn"
DEFAULT_VALUE_ATTRIBUTE="automountInformation"
EOF

# enable tls on the ldap lookup
cat <<EOF>/etc/autofs_ldap_auth.conf
<?xml version="1.0" ?>
<!--
This files contains a single entry with multiple attributes tied to it.
See autofs_ldap_auth.conf(5) for more information.
-->

<autofs_ldap_sasl_conf
        usetls="yes"
        tlsrequired="no"
        authrequired="no"
/>
EOF

chkconfig autofs on

# encrypt temporary filesystems
yum install -y cryptsetup-luks
# swap space
# (use "cryptsetup status /dev/mapper/swap" to verify swap encryption after reboot)
echo 'swap /dev/mapper/VolGroup-lv_swap /dev/urandom cipher=aes-cbc-essiv:sha256,size=128,swap' \
  > /etc/crypttab
sed -i 's/.*swap.*/\/dev\/mapper\/swap swap swap defaults 0 0/' /etc/fstab
# temporary file systems
echo 'none /tmp      tmpfs defaults,size=64m  0 0' >> /etc/fstab
echo 'none /var/tmp  tmpfs defaults,size=128m 0 0' >> /etc/fstab

# get rid of redundant sysfs entry to quiet the boot process
grep -v sysfs /etc/fstab > /tmp/fstab && mv -f /tmp/fstab /etc/fstab

# home directory encryption
# fuse-2.8.3-1.el6 works, fuse-2.8.3-3.el6_1 "fusermount -u" does not work.
yum install -y \
  fuse-2.8.3-1.el6 \
  fuse-encfs-1.7.4-1.el6.i686 \
  pwgen

# seems needed for fuse 2.8.3-4 
chmod a+x /bin/fusermount

cat <<EOF> /etc/profile.d/encfs.sh
#!/bin/bash

# check for interactive shell
[[ \$- != *i* ]] && return
# return if called by root
[[ \$UID -eq 0 ]] && return
# catch control+c
trap '' 2

# count encfs home mounts for user
count=\$(mount | grep -c "^encfs on .*\$USER")
until [[ \$count -ne 0 ]] ; do
    # decrypt and mount home directory
    # (only visible for the user, not for root)

    read -s -p "EncFS Password: " pw1st
    echo
    if [ ! -f /encfshome/\$USER/.encfs6.xml ] ; then
      read -s -p "Verify Password: " pw2nd
      echo
      until [[ \$pw1 == \$pw2 ]] ; do
        read -s -p "EncFS Password: " pw1st
        echo
        read -s -p "Verify EncFS Password: " pw2nd
        echo
      done
    fi

    echo
    echo --> Home directory encryption
    printf "\$pw1st\n" | encfs --stdinpass --standard /encfshome/\$USER \$HOME -o nonempty
    logger -p authpriv.info -t encfs -- \$HOME decrypted and mounted

    # pam only creates the home dir but not the validate dir
    # decrypt and mount validate directory
    # (only visible for the user, not for root)
    echo
    echo --> Validate directory encryption
    mkdir -p /validate/\$USER
    chmod 775 /validate/\$USER
    printf "\$pw1st\n" | encfs --stdinpass --standard /encfsvalidate/\$USER /validate/\$USER -o nonempty
    logger -p authpriv.info -t encfs -- /validate/\$USER decrypted and mounted

    # create 2nd key file for validation
    if [ ! -f /encfsvalidate/\$USER/.validate-encfs6.xml ] ; then
       pwrand=\$(pwgen 12 1)
       cp /encfsvalidate/\$USER/.encfs6.xml /encfsvalidate/\$USER/.validate-encfs6.xml
       printf "\$pw1st\n\$pwrand\n" \\
         |ENCFS6_CONFIG=/encfsvalidate/\$USER/.validate-encfs6.xml \\
         encfsctl autopasswd /encfsvalidate/\$USER
       echo
       echo ***************************************************************************
       echo /encfsvalidate/\$USER can also be mounted with these commands:
       echo "mkdir -p /validate/\$USER ; cd /validate"
       echo "ENCFS6_CONFIG=/encfsvalidate/\$USER/.validate-encfs6.xml \\\\"
       echo "  encfs /encfsvalidate/\$USER /validate/\$USER"
       echo "Password: \$pwrand"
       echo ***************************************************************************
       echo
    fi

    count=\$(mount | grep -c "^encfs on .*\$USER")
done

# set shell prompt
export PS1='[\u@\h \W]\\\\$ '

echo Directory \$HOME and /validate/\$USER decrypted and mounted successfully
cd
trap 2
EOF
chmod +x /etc/profile.d/encfs.sh

# load fuse kernel module at boot
cat <<EOF> /etc/sysconfig/modules/encfs.modules
#!/bin/bash
exec /sbin/modprobe fuse >/dev/null 2>&1
EOF
chmod +x /etc/sysconfig/modules/encfs.modules

yum install -y openssh-ldap
echo 'AuthorizedKeysCommand /usr/libexec/openssh/ssh-ldap-wrapper' >> /etc/ssh/sshd_config

# for ssh-ldap-helper
ln -s /etc/openldap/ldap.conf /etc/ssh/ldap.conf

# cacert.crt for ldap-tls access
mkdir -p /var/db/certs
echo '192.168.11.10:/export/certs /var/db/certs nfs nfsvers=4 0 0' >> /etc/fstab
test -d /etc/openldap/cacerts && mv /etc/openldap/cacerts /etc/openldap/cacerts.orig
ln -s /var/db/certs /etc/openldap/cacerts

# ldap config
yum install -y nss-pam-ldapd 
authconfig --update \
  --enablemkhomedir \
  --enableldap \
  --enablemd5 \
  --enableshadow \
  --enableldapauth \
  --enablelocauthorize \
  --ldapserver=ldaps://192.168.11.10:636 \
  --ldapbasedn='dc=g-pod'

service restart nslcd

# validate directories
mkdir /validate
chgrp users /validate
chmod 775 /validate
mkdir /encfsvalidate

# Syslog configuration
yum install -y rsyslog
mv -f /etc/rsyslog.conf /etc/rsyslog.conf.orig
chkconfig rsyslog on
cat <<EOF> /etc/rsyslog.conf
\$ModLoad imuxsock.so
\$ModLoad imklog.so
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
*.info;mail.none;authpriv.none;cron.none  /var/log/messages
authpriv.*                                /var/log/secure
mail.*                                    -/var/log/maillog
cron.*                                    /var/log/cron
*.emerg                                   *
local7.*                                  /var/log/boot.log
\$WorkDirectory /var/spppl/rsyslog
\$ActionQueueFileName fwdRule1
\$ActionQueueMaxDiskSpace 100m
\$ActionQueueSaveOnShutdown on
\$ActionQueueType LinkedList
\$ActionResumeRetryCount -1
*.* @@192.168.11.10:514
EOF

# It's nice to have man pages
yum install -y man

# clean up
yum clean all

# finish the installation
# halt -p
