#!/bin/bash
# 
# Copyright (C) Niklaus F.Schen.
# 

arm=`cpp -dM /dev/null | grep __arm__`
if [ $? -eq 0 ]; then
	arm='--enable_arm32'
else
	arm=''
fi

test -d objs || mkdir objs
test -d lib || mkdir lib
test -d Melon || git clone https://github.com/Water-Melon/Melon.git
dir=`pwd`
cd Melon
make clean
./configure --prefix=$dir/melon $arm
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
