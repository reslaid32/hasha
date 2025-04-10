#!/bin/bash

pkgver=$(cat VERSION)
pkgver_maj=$(echo $pkgver | cut -d'.' -f1)
pkgver_min=$(echo $pkgver | cut -d'.' -f2)
pkgver_pat=$(echo $pkgver | cut -d'.' -f3)

echo "#ifndef __hasha_imp_ver_h" > ./src/ver.h
echo "#define __hasha_imp_ver_h" >> ./src/ver.h
echo "#define __hasha_maj $pkgver_maj" >> ./src/ver.h
echo "#define __hasha_min $pkgver_min" >> ./src/ver.h
echo "#define __hasha_pat $pkgver_pat" >> ./src/ver.h
echo "#define __hasha_string_version \"$pkgver\"" >> ./src/ver.h
echo "#endif" >> ./src/ver.h

sed -i "s/^PROJECT_NUMBER *=.*/PROJECT_NUMBER         = \"$pkgver\"/" Doxyfile
doxygen Doxyfile

