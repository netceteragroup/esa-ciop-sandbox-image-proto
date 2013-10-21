sh -x ciop-server 2>&1     | tee build-server      && \
sh -x ciop-sandbox.sh 2>&1 | tee build-sandbox.log && \
VBoxManage export ciop-server ciop-sandbox --manifest -o  /tmp/ciop.ova
