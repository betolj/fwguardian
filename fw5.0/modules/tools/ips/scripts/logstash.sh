#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Script to Kibana Dashboard install
#

# Step 1 - Oracle Java install
echo "Logstash x Kibana Install - Ubuntu/Debian script"
[ ! -f /etc/debian_version ] && exit
FW_DIR=$(readlink -f "$(dirname $0)"/)
cd /opt

echo "- Step 1 / 5 - Oracle java install"
sudo add-apt-repository -y ppa:webupd8team/java
sudo apt-get update
sudo apt-get -y install oracle-java7-installer


# Install logstash
echo "- Step 2 / 5 - Logstash install"
echo 'deb http://packages.elasticsearch.org/logstash/1.4/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash.list
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D27D666CD88E42B4
sudo apt-get update
apt-get -f install logstash=1.4.2-1-2c0f5a1
sudo cp -f $FW_DIR/logstash.conf /etc/logstash/conf.d/

# Step 3 - Elasticsearch install
echo "- Step 3 / 5 - Elasticsearch install"
chown logstash.root /var/log/suricata/eve.json
chmod g+r /var/log/suricata/eve.json
sudo wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -
sudo echo 'deb http://packages.elasticsearch.org/elasticsearch/1.1/debian stable main' | sudo tee /etc/apt/sources.list.d/elasticsearch.list
sudo apt-get update
sudo apt-get -y install elasticsearch
sudo cp -f $FW_DIR/elasticsearch.yml /etc/elasticsearch
sudo update-rc.d elasticsearch defaults 95 10


# Step 4 - Kibana install
echo "- Step 4 / 5 - Kibana install"
sudo wget https://download.elasticsearch.org/kibana/kibana/kibana-3.1.0.tar.gz
sudo tar xvf kibana-3.1.0.tar.gz
sudo cat /opt/kibana-3.1.0/config.js | sed '/elasticsearch:/ s/:9200/:80/' > /tmp/config.tmp
sudo cp -f /tmp/config.tmp /opt/kibana-3.1.0/config.js
sudo mkdir -p /var/www/kibana3
sudo cp -R /opt/kibana-3.1.0/* /var/www/kibana3/


# Step 5 - Nginx install
echo "- Step 5 / 5 - Nginx installl"
sudo apt-get -y install nginx
sudo cp -f $FW_DIR/nginx.conf /etc/nginx/
sudo cp -f $FW_DIR/nginx.default.conf /etc/nginx/sites-available/default
sudo apt-get -y install apache2-utils
sudo htpasswd -c /etc/nginx/conf.d/kibana.myhost.org.htpasswd ipsadmin



# Restart log services
sudo service elasticsearch restart
sudo service logstash restart


#sudo mkdir -p /etc/pki/tls/certs
#sudo mkdir /etc/pki/tls/private
#sudo cd /etc/pki/tls; sudo openssl req -x509 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt
#cd -

#wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | apt-key add -
