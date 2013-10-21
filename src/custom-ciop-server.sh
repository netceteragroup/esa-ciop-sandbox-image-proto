#!/bin/bash
# Installation script for CIOP demo server
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
#     Adapter 1: Intel PRO/1000 MT Desktop (NAT) (port forwarding tcp: host 2222 -> guest 22)
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
IPADDR=192.168.11.10
NETMASK=255.255.255.0
TYPE=Ethernet
EOF
cat <<EOF> /etc/sysconfig/network
NETWORKING=yes
HOSTNAME=server.g-pod
EOF
service network restart

# local firewall rules for inbound traffic
lokkit --nostart --enabled \
  --service=ssh \
  --port=111:tcp \
  --port=111:udp \
  --port=514:tcp \
  --port=636:tcp \
  --port=662:tcp \
  --port=662:udp \
  --port=2049:tcp \
  --port=2049:udp \
  --port=32803:tcp \
  --port=32769:udp

# 111 rpc (for nfs)
# 389 ldap (unencrypted) or ldap-ssl (port 636)
# 514 rsyslog
# 662 statd (for nfs) 
# 2049 nfs4
# 32803,32769 lockd (for nfs)

# disable auto updates and selinux
sed -i 's/ENABLED="true"/ENABLED="false"/' /etc/sysconfig/yum-autoupdate
sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config

# get rid of redundant sysfs entry to quiet the boot process
grep -v sysfs /etc/fstab > /tmp/fstab && mv -f /tmp/fstab /etc/fstab

# nfs configuration
yum install nfs-utils -y
echo "/export/home 192.168.11.0/24(rw,async)" > /etc/exports
echo "/export/validate 192.168.11.0/24(rw,async)" >> /etc/exports

# store cacert.crt for ldap-tls
echo "/export/certs 192.168.11.0/24(ro)" >> /etc/exports
mkdir -p /export/certs

cat <<EOF>> /etc/sysconfig/nfs
MOUNTD_NFS_V2="no"
MOUNTD_NFS_V3="no"
RPCNFSDARGS="-N 2 -N 3"
STATD_PORT=662
LOCKD_TCPPORT=32803
LOCKD_UDPPORT=32769
EOF
chkconfig rpcbind on
chkconfig nfs on
chkconfig nfslock on

# ldap configuration
yum install -y openldap-clients openldap-servers nss-pam-ldapd

# prepare ldap cert
cd /etc/openldap/cacerts
openssl genrsa -out cert.key 2048
chown ldap.ldap cert.key
chmod 400 cert.key
openssl req -new -key cert.key -out cert.csr -subj "/C=IT/L=Default City/O=Default Company Ltd/CN=192.168.11.10"
openssl x509 -req -in cert.csr -signkey cert.key -out cert.crt
ln -s cert.crt cacert.crt
cp cacert.crt /export/certs
/usr/sbin/cacertdir_rehash /export/certs/

cat <<EOF> /etc/openldap/slapd.d/cn=config.ldif
dn: cn=config
objectClass: olcGlobal
cn: config
olcConfigFile: /etc/openldap/slapd.conf.bak
olcConfigDir: /etc/openldap/slapd.d
olcAllows: bind_v2
olcArgsFile: /var/run/openldap/slapd.args
olcAttributeOptions: lang-
olcAuthzPolicy: none
olcConcurrency: 0
olcConnMaxPending: 100
olcConnMaxPendingAuth: 1000
olcGentleHUP: FALSE
olcIdleTimeout: 0
olcIndexSubstrIfMaxLen: 4
olcIndexSubstrIfMinLen: 2
olcIndexSubstrAnyLen: 4
olcIndexSubstrAnyStep: 2
olcIndexIntLen: 4
olcLocalSSF: 71
olcPidFile: /var/run/openldap/slapd.pid
olcReadOnly: FALSE
olcReverseLookup: FALSE
olcSaslSecProps: noplain,noanonymous
olcSockbufMaxIncoming: 262143
olcSockbufMaxIncomingAuth: 16777215
olcThreads: 16
olcAccess: to filter="(|(cn=bob)(uid=bob))" by peername.regex=192.168.11.(10|20) read
olcAccess: to filter="(|(cn=alice)(uid=alice))" by peername.ip=192.168.11.10 read
olcAccess: to * by * read
olcTLSCACertificateFile: /etc/openldap/cacerts/cacert.crt
olcTLSCertificateFile: /etc/openldap/cacerts/cert.crt
olcTLSCertificateKeyFile: /etc/openldap/cacerts/cert.key
olcTLSCipherSuite: HIGH:MEDIUM:+TLSv1:!SSLv2:+SSLv3
olcTLSVerifyClient: never
olcToolThreads: 1
olcWriteTimeout: 0
structuralObjectClass: olcGlobal
entryUUID: 6d1d7b06-0617-1031-93d7-e5e4e252d79c
creatorsName: cn=config
createTimestamp: 20120319135901Z
entryCSN: 20120319135901.848294Z#000000#000#000000
modifiersName: cn=config
modifyTimestamp: 20120319135901Z
EOF

cat <<EOF> /etc/openldap/slapd.d/cn=config/olcDatabase={2}bdb.ldif
dn: olcDatabase={2}bdb
objectClass: olcDatabaseConfig
objectClass: olcBdbConfig
olcDatabase: {2}bdb
olcSuffix: dc=g-pod
olcAddContentAcl: FALSE
olcLastMod: TRUE
olcMaxDerefDepth: 15
olcReadOnly: FALSE
olcRootDN: cn=root,dc=g-pod
olcRootPW: secret
olcSyncUseSubentry: FALSE
olcMonitoring: TRUE
olcDbDirectory: /var/lib/ldap
olcDbCacheSize: 1000
olcDbCheckpoint: 1024 15
olcDbNoSync: FALSE
olcDbDirtyRead: FALSE
olcDbIDLcacheSize: 0
olcDbIndex: objectClass pres,eq
olcDbIndex: cn pres,eq,sub
olcDbIndex: uid pres,eq,sub
olcDbIndex: uidNumber pres,eq
olcDbIndex: gidNumber pres,eq
olcDbIndex: ou pres,eq,sub
olcDbIndex: loginShell pres,eq
olcDbIndex: mail pres,eq,sub
olcDbIndex: sn pres,eq,sub
olcDbIndex: givenName pres,eq,sub
olcDbIndex: memberUid pres,eq,sub
olcDbIndex: nisMapName pres,eq,sub
olcDbIndex: nisMapEntry pres,eq,sub
olcDbLinearIndex: FALSE
olcDbMode: 0600
olcDbSearchStack: 16
olcDbShmKey: 0
olcDbCacheFree: 1
olcDbDNcacheSize: 0
structuralObjectClass: olcBdbConfig
entryUUID: 8f37a72c-03db-1031-8c78-097b4b0e376e
creatorsName: cn=config
createTimestamp: 20120316174526Z
entryCSN: 20120316174526.927746Z#000000#000#000000
modifiersName: cn=config
modifyTimestamp: 20120316174526Z
EOF

cat <<EOF> /etc/openldap/slapd.d/cn=config/cn=schema/cn={12}autofs.ldif
dn: cn={12}autofs
objectClass: olcSchemaConfig
cn: autofs
olcAttributeTypes: {0}( 1.3.6.1.1.1.1.25 NAME 'automountInformation' DESC 'Inf
 ormation used by the autofs automounter' EQUALITY caseExactIA5Match SYNTAX 1.
 3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
olcObjectClasses: {0}( 1.3.6.1.1.1.1.13 NAME 'automount' DESC 'An entry in an
 automounter map' SUP top STRUCTURAL MUST ( cn $ automountInformation $ object
 class ) MAY description )
olcObjectClasses: {1}( 1.3.6.1.4.1.2312.4.2.2 NAME 'automountMap' DESC 'An gro
 up of related automount objects' SUP top STRUCTURAL MUST ou )
EOF

cat <<EOF> /etc/openldap/slapd.d/cn=config/cn=schema/cn={14}ldappubkey.ldif
dn: cn={14}ldappubkey
objectClass: olcSchemaConfig
cn: ldappubkey
olcAttributeTypes: {0}( 1.3.6.1.4.1.24552.500.1.1.1.13 NAME 'sshPublicKey' DES
 C 'MANDATORY: OpenSSH Public key' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.
 1.1466.115.121.1.40 )
olcObjectClasses: {0}( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME 'ldapPublicKey' DESC
  'MANDATORY: OpenSSH LPK objectclass' SUP top AUXILIARY MUST ( sshPublicKey $
  uid ) )
structuralObjectClass: olcSchemaConfig
entryUUID: 338bf1fa-03c5-1031-9629-ab50fe32c950
creatorsName: cn=config
createTimestamp: 20120316150524Z
entryCSN: 20120316150524.205114Z#000000#000#000000
modifiersName: cn=config
modifyTimestamp: 20120316150524Z
EOF

cat <<EOF> /etc/openldap/g-pod.ldif
dn: dc=g-pod
dc: g-pod
objectClass: domain
objectClass: top

dn: ou=people,dc=g-pod
ou: people
objectClass: top
objectClass: organizationalUnit

dn: ou=group,dc=g-pod
ou: people
objectClass: top
objectClass: organizationalUnit

dn: uid=bob,ou=people,dc=g-pod
cn: Ronnie Brunner
description: allowed bob,192.168.11.(10|20)
gecos: bob
gidNumber: 100
homeDirectory: /home/bob
loginShell: /bin/bash
uidNumber: 5000
uid: bob
objectClass: account
objectClass: posixAccount
objectClass: shadowAccount
objectClass: top
objectClass: ldapPublicKey
sshPublicKey: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

dn: uid=alice,ou=people,dc=g-pod
cn: Emmanuel Mathot
description: allowed alice,192.168.11.10
gecos: alice
gidNumber: 100
homeDirectory: /home/alice
loginShell: /bin/bash
uidNumber: 5001
uid: alice
objectClass: account
objectClass: posixAccount
objectClass: shadowAccount
objectClass: top
objectClass: ldapPublicKey
sshPublicKey: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

dn: cn=users,ou=group,dc=g-pod
cn: users
gidNumber: 100
memberUid: bob
memberUid: alice
objectClass: posixGroup
objectClass: top

dn: cn=fuse,ou=group,dc=g-pod
cn: fuse
gidNumber: 498
memberUid: bob
memberUid: alice
objectClass: posixGroup
objectClass: top

dn: ou=automount,dc=g-pod
ou: automount
objectClass: top
objectClass: organizationalUnit

dn: ou=auto.master,ou=automount,dc=g-pod
ou: auto.master
objectClass: top
objectClass: automountMap

dn: cn=/encfshome,ou=auto.master,ou=automount,dc=g-pod
cn: /encfshome
objectClass: top
objectClass: automount
automountInformation: ldap:ou=auto.encfshome,ou=automount,dc=g-pod

dn: cn=/encfsvalidate,ou=auto.master,ou=automount,dc=g-pod
cn: /encfsvalidate
objectClass: top
objectClass: automount
automountInformation: ldap:ou=auto.encfsvalidate,ou=automount,dc=g-pod

dn: ou=auto.encfshome,ou=automount,dc=g-pod
ou: auto.encfshome
objectClass: top
objectClass: automountMap

dn: ou=auto.encfsvalidate,ou=automount,dc=g-pod
ou: auto.encfsvalidate
objectClass: top
objectClass: automountMap

dn: cn=alice,ou=auto.encfshome,ou=automount,dc=g-pod
cn: alice
objectClass: top
objectClass: automount
automountInformation: -fstype=nfs4,intr 192.168.11.10:/export/home/alice

dn: cn=alice,ou=auto.encfsvalidate,ou=automount,dc=g-pod
cn: alice
objectClass: top
objectClass: automount
automountInformation: -fstype=nfs4,intr 192.168.11.10:/export/validate/alice

dn: cn=bob,ou=auto.encfshome,ou=automount,dc=g-pod
cn: bob
objectClass: top
objectClass: automount
automountInformation: -fstype=nfs4,intr 192.168.11.10:/export/home/bob

dn: cn=bob,ou=auto.encfsvalidate,ou=automount,dc=g-pod
cn: bob
objectClass: top
objectClass: automount
automountInformation: -fstype=nfs4,intr 192.168.11.10:/export/validate/bob
EOF

cat <<EOF> /etc/sysconfig/ldap
SLAPD_LDAP=no
SLAPD_LDAPS=yes
EOF

slapadd -l /etc/openldap/g-pod.ldif
chown -R ldap:ldap /var/lib/ldap
chkconfig slapd on
service slapd start

# user configuration
authconfig --update \
  --enablelocauthorize \
  --enableldap \
  --ldapserver=ldaps://192.168.11.10:636 \
  --ldapbasedn='dc=g-pod'

mkdir -p /export/home/bob
mkdir -p /export/validate/bob
chown bob:users /export/home/bob
chown bob:users /export/validate/bob

mkdir -p /export/home/alice
mkdir -p /export/validate/alice
chown alice:users /export/home/alice
chown alice:users /export/validate/alice

# Syslog configuration
yum install -y rsyslog
mv -f /etc/rsyslog.conf /etc/rsyslog.conf.orig
chkconfig rsyslog on
cat <<EOF> /etc/rsyslog.conf
\$ModLoad imuxsock.so
\$ModLoad imklog.so
\$ModLoad imtcp.so
\$InputTCPServerRun 514
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
*.info;mail.none;authpriv.none;cron.none /var/log/messages
authpriv.*                               /var/log/secure
mail.*                                   -/var/log/maillog
cron.*                                   /var/log/cron
*.emerg                                  *
local7.*                                 /var/log/boot.log
EOF

# It's nice to have man pages
yum install -y man

# clean up
yum clean all

# finish the installation
# halt -p
