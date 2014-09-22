#!/bin/bash
# 
# Remove all firewall qdisc 
# - This was based in last cbqinit script project
#

[ "$1" == "" ] && exit

ip=$(which ip)
tc=$(which tc)

### Obtendo a lista dispositivos de rede
tf_device_list () {
   ip link show| sed "s/@\([a-z0-9]\+\):/:/g;" | sed -n "/^[0-9]/ \
      { s/^[0-9]\+: \([.a-z0-9]\+\): .*/\1/;  p; }"
} # tf_device_list


### Removendo a classe root do dispositivo $1
tf_device_off () {
   $tc qdisc del dev $1 root 2> /dev/null
   $tc qdisc del dev $1 ingress 2>/dev/null
} # tf_device_off


### Remove todos os dispositivos CBQ/HTB 
tf_off () {
   for dev in $(tf_device_list); do
      tf_device_off $dev
   done
} # tf_off

tf_off
