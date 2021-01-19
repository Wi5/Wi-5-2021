# odin-enabled click-router for Openwrt 18.06
This package can be downloaded and added as local repository to Openwrt. The Openwrt image after cross-compile ewill include click-router that is modified to support Odin client<sup>1</sup>. 
To build the Openwrt 18.0.6 image:
Install [Prerequisites](https://openwrt.org/docs/guide-developer/build-system/install-buildsystem), this is the list of packges which were installed on Ubuntu 18 but there may be more requirments:

` sudo apt-get update`  
` sudo apt-get --yes  install build-essential subversion libncurses5-dev zlib1g-dev gawk gcc-multilib flex gettext subversion-tools  python unzip g++ python3 python3-distutils libncurses5-dev file libssl-dev wget libelf-dev ecj fastjar java-propose-classpath xsltproc python-dev libssl-dev libncurses5-dev git ccache xsltproc zip`    

Then download this package:
`git clone https:\\github.com\sayed-amir\odin-click-router.git`  

There a folder for click-router package and a script to apply [ath9k patch](https://github.com/Wi5/odin-wi5/blob/master/odin-patch-driver-ath9k/ath9k-bssid-mask.patch).  
Download Openwrt 18.0.6.9:  
`git clone `  
Copy the ath9k patch to the openwrt folder:  
`cp odin-click-router/ath9k-patch.sh openwrt/`  
Create local package directory and cp click-router into it:  
`cd openwrt/`  
`mkdir mypackages`  
`cp -r ../odin-click-router/click-router/  mypackages/` 
Edit feeds.conf to add the local repository:  
`src-link custom /home/ubuntu/openwrt/mypackages`  

Note that the `/home/ubuntu/openwrt/mypackages` should be replaced by absolute address of mypackage folder in your linux.


1 - This install click version (2020/10/26) on Openwrt 18.06.8. The image has been tested on TP-Link AR1750 (ARCHER c7 v5).
