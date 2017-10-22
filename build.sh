#!/bin/bash
# 
# Copyright (C) Niklaus F.Schen.
# 

test -d objs || mkdir objs
test -d lib || mkdir lib
test -d Melon || git clone https://github.com/Water-Melon/Melon.git
dir=`pwd`
cp -f mln_global.h Melon/include/
cd Melon
make clean
./configure --prefix=$dir/melon
make
make install
cp -f lib/* ../lib
cd ..
#check ld.so.conf
lib="$dir/melon/lib/"
exist=0
cat /etc/ld.so.conf | while read line
do
	if [ "$line" = "$lib" ]; then
		let exist+=1
	fi
	echo $exist > .tmp
done
exist=`cat .tmp`
rm -fr .tmp
if [ $exist = "0" ]; then
	echo $lib >> /etc/ld.so.conf
	ldconfig
fi
