# odin-enabled click-router for Openwrt 18.06
This package can be downloaded and added as a local repository to Openwrt. The Openwrt image after cross-compile will include click-router that is modified to support Odin client<sup>1</sup>. 
To build the Openwrt 18.0.6 image:
Install [Prerequisites](https://openwrt.org/docs/guide-developer/build-system/install-buildsystem), this is the list of packages which were installed on Ubuntu 18 but there may be more requirements:

` sudo apt-get update`  
` sudo apt-get --yes  install build-essential subversion libncurses5-dev zlib1g-dev gawk gcc-multilib flex gettext subversion-tools  python unzip g++ python3 python3-distutils libncurses5-dev file libssl-dev wget libelf-dev ecj fastjar java-propose-classpath xsltproc python-dev libssl-dev libncurses5-dev git ccache xsltproc zip`    

Then download this package:
`git clone https:\\github.com\sayed-amir\odin-click-router.git`  

There a folder for click-router package and a script to apply [ath9k patch](https://github.com/Wi5/odin-wi5/blob/master/odin-patch-driver-ath9k/ath9k-bssid-mask.patch).  
Download Openwrt 18.0.6.9:  
`git clone -b openwrt-18.06 https://github.com/openwrt/openwrt.git openwrt `  


Create local package directory and copy click-router into it:  
`cd openwrt/`  
`mkdir mypackages`  
`cp -r ../odin-click-router/click-router/  mypackages/` 

Edit feeds.conf to add the local repository to the last line:  
`...`  
`src-git routing https://git.openwrt.org/feed/routing.git^0e63ef9276bf41c0d4176127f9f047343b8ffe32`  
`src-git telephony https://git.openwrt.org/feed/telephony.git^8ecbdabc7c5cadbe571eb947f5cd333a5a785010`  
`src-link custom /home/ubuntu/openwrt/mypackages`  

Note that the `/home/ubuntu/openwrt/mypackages` should be replaced by an absolute address of mypackages folder in your Linux.


Copy the ath9k patch to the Openwrt folder:  
`cp ../odin-click-router/ath9k-patch.sh .`  
`chmod 777 ath9k-patch.sh`  
`./ath9k-patch.sh`  

Update and install feeds:  
`./scripts/feeds update -a`  
`./scripts/feeds install -a`  


Then configure OpenWrt make by:  
`make menuconfig`  

select only necessary packages since there is an image size limit depending on your wireless router storage. Particularly find `click-router` at the bottom of the list. Save the configuration as `.config`.

Check `clcik-router` selection in `.config` file:  
`grep click-router .config`  

if it shows `# CONFIG_PACKAGE_click-router is not set`, it is not selected to be cross-compiled and installed. Edit `.config` file and modify the line to:
`CONFIG_PACKAGE_click-router=y`  


Then run:  
`make`

or if you want to have logs in a file:
`make V=s 2>&1 | tee build.log | grep -i -E "^make.*(error|[12345]...Entering dir)"`  

If everything goes well, the image file (`.bin`) and also the Click installation file (`.ipk`) should be found in `openwrt/bin/`. 


1 - This installs click version (2020/10/26) on Openwrt 18.06.8. The image has been tested on TP-Link AR1750 (ARCHER c7 v5).
