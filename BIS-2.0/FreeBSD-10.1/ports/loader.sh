#!/bin/sh

rel=`uname -r`
ver=${rel%-*}
major=${ver%.*}
minor=${ver#*.}

if [ $major -lt 10 ]; then
   sed -i "" '/Loader labels for Hyper-v BIS driver/d' /boot/loader.conf
   sed -i "" '/hv_vmbus_load/d' /boot/loader.conf
   sed -i "" '/hv_utils_load/d' /boot/loader.conf
   sed -i "" '/hv_storvsc_load/d' /boot/loader.conf
   sed -i "" '/hv_netvsc_load/d' /boot/loader.conf
   sed -i "" '/hv_ata_pci_disengage_load/d' /boot/loader.conf
   
   echo  "# Loader labels for Hyper-v BIS drivers -do not modify" >> /boot/loader.conf
   echo  'hv_vmbus_load="YES"' >> /boot/loader.conf
   echo  'hv_utils_load="YES"'  >> /boot/loader.conf
   echo  'hv_storvsc_load="YES"'  >> /boot/loader.conf
   echo  'hv_netvsc_load="YES"'  >> /boot/loader.conf
   echo  'hv_ata_pci_disengage_load="YES"'  >>/boot/loader.conf   
fi

if [ $major -eq 10 ]; then
	if [ $minor -eq 0 ]; then
        sed -i "" '/Loader labels for Hyper-V KVP drivers/d' /etc/rc.conf 
        sed -i "" '/hv_kvp_load/d' /etc/rc.conf
		echo  '# Loader labels for Hyper-V KVP drivers -do not modify' >> /boot/loader.conf
        echo  'hv_kvp_load="YES"' >> /boot/loader.conf
		
        sed -i "" '/Label for KVP daemon/d' /etc/rc.conf
        sed -i "" '/hv_kvp_daemon_enable/d' /etc/rc.conf
        echo  '# Label for KVP daemon -do not modify' >> /etc/rc.conf
        echo  'hv_kvp_daemon_enable="YES"' >> /etc/rc.conf		
    elif [ $minor -eq 1 ]; then
        sed -i "" '/Loader labels for Hyper-v BIS driver/d' /boot/loader.conf
        sed -i "" '/hv_storvsc_port_load/d' /boot/loader.conf
        sed -i "" '/hv_utils_port_load/d' /boot/loader.conf
		
		echo  "# Loader labels for Hyper-v BIS drivers -do not modify" >> /boot/loader.conf
        echo  'hv_storvsc_port_load="YES"'  >> /boot/loader.conf
        echo  'hv_utils_port_load="YES"'  >> /boot/loader.conf
    fi
fi

exit 0
