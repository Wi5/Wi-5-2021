# odin-enabled click-router for Openwrt 18.06
This package can be downloaded and added as local repository to Openwrt. The Openwrt image after cross-compile ewill include click-router that is modified to support Odin client<sup>1</sup>. 
To build the Openwrt 18.0.6 image:
Install [Prerequisites](https://openwrt.org/docs/guide-developer/build-system/install-buildsystem), this is the list of packges which were installed on Ubuntu 18 but there amy be more requirments:

` sudo apt-get update`  
` sudo apt-get --yes --force-yes  install build-essential subversion libncurses5-dev zlib1g-dev gawk gcc-multilib flex git-core gettext subversion-tools ncurses-dev svnk python unzip g++ python3 python3-distutils libncurses5-dev file libssl-dev wget libelf-dev ecj fastjar java-propose-classpath xsltproc python-dev libssl-dev libncurses5-dev git ccache xsltproc zip`  

1 - This install click version (2020/10/26) on Openwrt 18.06.8. The image has been tested on TP-Link AR1750 (ARCHER c7 v5).
