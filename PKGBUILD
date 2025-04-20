pkgname=hasha

pkgver=$(cat "VERSION")
pkgver_maj=$(echo $pkgver | cut -d'.' -f1)
pkgver_min=$(echo $pkgver | cut -d'.' -f2)
pkgver_pat=$(echo $pkgver | cut -d'.' -f3)

pkgrel=0
pkgdesc="Standalone lightweight hashing library"
arch=('x86_64')
url="https://github.com/reslaid32/hasha.git"
license=('MIT')
depends=('glibc')
makedepends=('make' 'gcc')
options=('!debug')

do_chck=true

build() {
  cd "$srcdir/.."
  make clean all
}

check() {
  if $do_chck; then
    cd "$srcdir/.."
    export LD_LIBRARY_PATH="$srcdir/../lib"
    make check
  fi
}

package() {
  cd "$srcdir/.."
  make DESTDIR="$pkgdir" PREFIX=/usr install
}
