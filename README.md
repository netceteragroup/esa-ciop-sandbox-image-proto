esa-ciop-sandbox-image-proto
============================

This repository contains a prototype for cloud server and sandbox image creation concept for the ESA CIOP project. The concept calls for:

* All files and communication to be encrypted
* Images to be immutable (read-only and re-created if changes are desired)
* Limited writeable files are remote mounted via (user-space encrypted) NFS

The base (RedHat-based Scientifix Linux) images and their cloud support were configured/created using the apparently-now-deprecated open source boxgrinder appliance creaton tool, together with these highly customized scripts. VirtualBox is used for local development of these image creation scripts. Then the images are re-generated for specific deployment on a particular cloud provider.

* [ESA](http://esa.int)
* [ESA's Earth Observation CIOP project](http://ciop.eo.esa.int)
* [Boxgrinder](http://boxgrinder.org)

Overview
---------------------

This prototype generates two types of cloud-agnostic images - 1) a server image for providing directory and file storage services and 2) a client or sandbox image for accessing the served files and services.

There are three classes of files that the server serves:
 * Effectively Insecure e.g. /data - the imagery data
 * 1-party secure e.g. /home - source code accessable only by the end-user
 * 2-party secure e.g. /validate - binaries modules accessable by the end-user and a validating party

All of the secure files are encrypted/decrypted in userspace on the client-side using encfs.

Details
---------------------

The BUILD.sh script generates the two images for use with VirtualBox by default

 * Server                       (port 2222 via localhost NAT)
 * Sandbox (example client)     (port 3333 via localhost NAT)

The scripts create not only the two virtual machines but also an .ova file that contains both images. You should be able to import the images and start them like this:

```
  VBoxManage import ciop.ova
  VirtualBox startvm ciop-server &
  VirtualBox startvm ciop-sandbox &
```

Server
------

You should wait for the server to be fully up before booting the sandbox(es) because the server runs services needed by the client(s) including: LDAP and NFS.

We have not (yet) disabled root ssh access so you can login to the two machines via the ports mentioned above

```
  ssh -p 2222 root@localhost
  ssh -p 3333 root@localhost
```

Root credentials for console login: root/secret  (This should be disabled)

There is nothing to do on the server, but logging in as root shows that the home (and validate) directories are indeed encrypted and not readable by anyone. See:

```
  /export/home/alice
  /export/home/bob
  /export/validate/alice
  /export/validate/bob
```

(These directories are empty before alice or bob resp. have logged in for the first time.)

ACLs
----

The example ACL (access control list) configuration has one line per user listing which machines s/he is allowed to access (and a final catch all rule):

```
  to filter="(|(cn=bob)(uid=bob))" by peername.regex=192.168.11.(10|20) read
  to filter="(|(cn=alice)(uid=alice))" by peername.ip=192.168.11.10 read
  to * by * read
```

In this particular example setup, both users are visible (via "ldapsearch -x") on the server, but only bob is allowed access to the sandbox/client (at 192.168.11.20).

This can be verified by trying to manually run the ssh-ldap-wrapper:

```
 [root@client ~]# /usr/libexec/openssh/ssh-ldap-wrapper bob
 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 [root@client ~]# /usr/libexec/openssh/ssh-ldap-wrapper alice
 [root@client ~]# 
```

A stub script "usermgmt.sh" shows what how a scriptable user management program could look. It should:

 * add/remove/update the "people" entry for a person
 * regenerate the ACL rules above.

It is standard in this setup to store the public key in sshPublicKey.  It is NOT standard (but rather a proof of concept) to store the per-user ACL rules in the user's "description" field to allow easy (re)-generation of the ACL rules (as prototyped in the "usermgmt.sh" script).
 
Client
------

The client VM is now not configured for any specific user -> the same VM could/should be used for all sandboxes w/o need to patch the configuration (ssh keys are kept centrally on the server). 

Root credentials for console login: root/secret  (This should be disabled)

To log on to the client with ssh, the private key for alice (or bob) must be saved locally.


First time client login to a sandbox
------------------------------------

You can use the portal to download your certificate/private key (xxx.pem) and use it to login to your sandbox (in this case, we are using the NAT tunnel at port 3333 on the localhost). Remember that the key file e.g. bob.pem must be chmod 600 or similar for ssh to accept it.

	ssh -i bob.pem -p 3333 bob@localhost

This will create the encrypted home and validate directories and ask for a pass phrase to encrypt it with.

If you then create a file in the home directory, you will see it on the NFS server, but encrypted.

Repeated logins will not ask for the pass phrase, as it stays mounted for that user. It will stay mounted as long as the VM is not shut down and restarted. If/when that happens, the user must retype the pass phrase he provided when the file system was created.

Additionally, the first log-on script also creates a random *additional* password that allows for the validate directory to be decrypted. In the current demo, this password is only output to the shell including a short note that tells you how to decrypt the validate directory using the random password.

In the real implementation, this random password could be sent to the admin who will look at the validate directory in the future. And since this additional configuration is actually stored on the server (for john in (/export/validate/john/.validate-encfs6.xml), it is very easy to e.g. make sure that the password must be changed within 24 hours by the recipient. If he doesn't do that, the random password can be deleted. And since with any valid password for the validate file system, any new random passwords could be added, this mechanism (with some easy script magic) would also allow to add proxies that can access the encrypted data in the future or temporary etc. etc. (the same is obviously true for the home directory even though it's not a requirement).

First time login details
------------------------

First time login appears as follows...

```
Creating directory '/home/bob'.

Appliance:      ciop-sandbox appliance 1.0
Hostname:       client.g-pod

EncFS Password: ******
Verify Password: ******

Creating new encrypted volume.
Standard configuration selected.

Configuration finished.  The filesystem to be created has
the following properties:
Filesystem cipher: "ssl/aes", version 3:0:2
Filename encoding: "nameio/block", version 3:0:1
Key Size: 192 bits
Block Size: 1024 bytes
Each file contains 8 byte header with unique IV data.
Filenames encoded using IV chaining mode.
File holes passed through to ciphertext.

Now you will need to enter a password for your filesystem.
You will need to remember this password, as there is absolutely
no recovery mechanism.  However, the password can be changed
later using encfsctl.

Creating new encrypted volume.
Standard configuration selected.

Enter current Encfs password
Enter new Encfs password
Volume Key successfully updated.

Home Validate
/encfsvalidate/bob can also be mounted with these commands:
mkdir -p /validate/bob ; cd /validate
ENCFS6_CONFIG=/encfsvalidate/bob/.validate-encfs6.xml \
  encfs /encfsvalidate/bob /validate/bob
Password: zohnieceilai
Home Validate

Directory /home/bob and /validate/bob decrypted and mounted successfully
```
