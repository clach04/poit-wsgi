#!/bin/sh
version=`awk '/POIT_VERSION = ".*"/ {gsub(/"/, "", $3); print $3}' poit.py`
d="poit-${version}"
f="${d}.tar.bz2"

echo Making $f
if [ ! -d dist ]; then
  mkdir dist || exit 1
fi


echo cleaning pyc files
cd openid
rm `find . -name \*\.pyc`
cd ..


cd dist
rm -rf $d
mkdir $d
cp ../poit.py ../poit.css ../poit.conf.example ../README $d
cp -R ../openid $d

tar -cjf $f $d
md5sum $f > "${f}.md5"
sha1sum $f > "${f}.sha1"

rm -rf $d

cat "${f}.md5"
cat "${f}.sha1"
