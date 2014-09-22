#!/bin/bash
#
# - Steps to build Suricata-2.0.2 in Debian
#

# - Install main libs
#sudo apt-get -y update
sudo apt-get -y install libpcre3-dev
sudo apt-get -y install libyaml-dev
sudo apt-get -y install libpcap-dev
sudo apt-get -y install libcap-ng-dev
sudo apt-get -y install libmagic-dev
sudo apt-get -y install zlib1g-dev
sudo apt-get -y install libgeoip-dev
sudo apt-get -y install libjansson-dev
sudo apt-get -y install libnspr4-dev
sudo apt-get -y install libnfnetlink-dev
sudo apt-get -y install libnetfilter-queue-dev
sudo apt-get -y install fakeroot
sudo apt-get -y install libnss

# - Add source list
#if [ ! -f /etc/apt/sources.list.d/unstable.sources.list ]; then
#   echo "deb http://ftp.debian.org/debian testing main contrib non-free" > /etc/apt/sources.list.d/unstable.sources.list
#   echo "deb http://ftp.debian.org/debian/ unstable main" >> /etc/apt/sources.list.d/unstable.sources.list
#   echo "deb http://ftp.debian.org/debian/ wheezy-backports main" >> /etc/apt/sources.list.d/unstable.sources.list
#   echo "deb-src http://http.us.debian.org/debian unstable main" >> /etc/apt/sources.list.d/unstable.sources.list
#   sudo apt-get -y update
#fi
echo "deb-src http://http.us.debian.org/debian unstable main" > /etc/apt/sources.list.d/unstable.sources.list
sudo apt-get -y update


# - Install from unstable mirror (dont work well)
#apt-get -y -t unstable install suricata


# - Steps to build from source code
cd /tmp
mkdir -p src/debian/; cd src/debian

# - Building and install libhtp
sudo apt-get -y source libhtp=0.5.12-1
cd libhtp-0.5.12
sudo apt-get -y build-dep libhtp
fakeroot debian/rules binary
cd ..
dpkg --install libhtp-dev_0.5.12-1_amd64.deb libhtp1_0.5.12-1_amd64.deb
rm -rf /tmp/src/debian/libhtp-0.5.12

# - Building and install suricata
sudo apt-get -y source suricata=2.0.3-1
cd suricata-2.0.3
sed -i '/CONFIGURE_ARGS/ s/--enable-prelude //;' /tmp/src/debian/suricata-2.0.3/debian/rules
sed -i 's/disable-coccinelle \\/disable-coccinelle/' /tmp/src/debian/suricata-2.0.3/debian/rules
sed -i '/^ifneq/d' /tmp/src/debian/suricata-2.0.3/debian/rules
sed -i '/^endif/d' /tmp/src/debian/suricata-2.0.3/debian/rules
sed -i '/ENABLE_LUAJIT/d' /tmp/src/debian/suricata-2.0.3/debian/rules
sudo apt-get -y build-dep suricata
fakeroot debian/rules binary
cd ..
dpkg --install suricata_2.0.3-1_amd64.deb
rm -rf /tmp/src/debian/suricata-2.0.3
