pkgname=hasha
pkgver=2.1.8
pkgrel=0
pkgdesc="Standalone lightweight hashing library"
arch=('x86_64')
url="https://github.com/reslaid32/hasha.git"
license=('MIT')
depends=('glibc')
makedepends=('make' 'gcc')

check_before_install=true

build() {
  cd "$srcdir/.."
  make clean all
}

check() {
  if $check_before_install; then
    cd "$srcdir/.."
    export LD_LIBRARY_PATH="$srcdir/../lib"
    make check
  fi
}

package() {
  cd "$srcdir/.."
  make DESTDIR="$pkgdir" PREFIX=/usr install
}
