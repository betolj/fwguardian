#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Only for develop purposes (m5sum of firewall modules)
#

[ "$1" == "" ] && exit

FW_DIR=$1
MY_VER=$2
MY_DIR=$(readlink -f "$(dirname $0)"/)
forcechk=0

### Check directory control version
if [ ! -d $MY_DIR/../version ]; then
    mkdir $MY_DIR/../version
    echo "0" > $MY_DIR/../version/VER
    forcechk=1
fi

### For new versions (desenv)
if [ "$1" == "--rebuild-md5" ] || [ "$forcechk" -eq 1 ] ; then
  find $MY_DIR $MY_DIR/../webauth/*/*.pl -print -exec md5sum 2>/dev/null {} \; | grep -v '^\/' | \
	sed 's/ .*\/modules\//  /' | sort > $MY_DIR/../version/vermod.md5

  if [ "$forcechk" -eq 0 ]; then
    echo "Finished rebuild!"
    exit
  fi
fi

### Search fwguardian version
if [ ! -f $FW_DIR/version/VER ]; then
  forcechk=1
  echo $MY_VER > $FW_DIR/version/VER
else
  curver=$(cat $FW_DIR/version/VER)
fi


if [ "$curver" != "$MY_VER" ] || [ "$forcechk" -eq 1 ]; then

  ### Calc the modules md5 
  find $MY_DIR $MY_DIR/../webauth/*/*.pl -print -exec md5sum 2>/dev/null {} \; | grep -v "^\.\|^modules" | \
	sed 's/\..*\///' | sort > $MY_DIR/../version/mymod.md5

  ### Check md5 for this install
  while read line; 
  do
    fmod=$(cat $FW_DIR/version/vermod.md5 | grep "$line" | wc -l)
    [ "$fmod" -ne 1 ] && echo "WARNING... $(echo $line | awk '{print $2}') is out-of-date!"
  done < $FW_DIR/version/mymod.md5

  echo $MY_VER > $FW_DIR/version/VER
  exit 0

else
  exit 1
fi
