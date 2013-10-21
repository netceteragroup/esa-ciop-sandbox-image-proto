#!/bin/sh

#
# Incomplete (non-working) psuedo code for a user management script
#

NEWUSER=jdoe

# create a new user entry - increment the gid and fetch user's public key
cat << EOF > /tmp/newuser.$$
dn: uid=bob,ou=people,dc=g-pod
changetype: add
cn: $NEWUSER
gecos: $NEWUSER
gidNumber: 100
homeDirectory: /home/$NEWUSER
loginShell: /bin/bash
uidNumber: `ldapsearch -x | grep uidNumber | awk '{print $NF + 1}' | sort -nr | head -1`
uid: $NEWUSER
objectClass: account
objectClass: posixAccount
objectClass: shadowAccount
objectClass: top
objectClass: ldapPublicKey
sshPublicKey: `curl -s -o - --insecure "https://some.place.com/certificatedownload?user=alice&format=Ppem" | openssl x509 -inform pem -in /dev/stdin -noout -pubkey | ssh-keygen -f /dev/stdin -i -m PKCS8`
EOF

# create per-host/per-user acl list from ldap descriptions
cat << EOF > /tmp/newacls.$$
for e in `ldapsearch -x | grep allowed | awk '{print $NF}'`; do
  echo $e | awk -F, '{printf "olcAccess: to filter=\"(|(cn=%s)(uid=%s))\" by peername.regex=%s read\n", $1, $1, $2}'
done
printf "olcAccess: to * by * read\n"
EOF

# fix this to add the specific new user above
ldapmodify -f /tmp/newuser.$$

# fix this to remove all current olcAccess rules
ldapmodify << EOF
changetype: modify
delete: olcAccess
EOF

# fix this to add all newly created acl rules
ldapmodify -f /tmp/newacls.$$
