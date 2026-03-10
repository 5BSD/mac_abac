!# /bin/bash

scp /home/koryheard/Projects/vLabelMACF/kernel/mac_vlabel.ko root@192.168.7.134:/boot/kernel/
scp /home/koryheard/Projects/vLabelMACF/tools/vlabelctl root@192.168.7.134:/usr/local/bin/
scp -r /home/koryheard/Projects/vLabelMACF/tests root@192.168.7.134:/root/

