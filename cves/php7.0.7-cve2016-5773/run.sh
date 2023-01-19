set -eu

[ -f php-7.0.7.tar.gz ] || \
    wget "https://www.php.net/distributions/php-7.0.7.tar.gz"
[ -d php-7.0.7.tar.gz ] || \
    tar xf php-7.0.7.tar.gz

cd php-7.0.7
patch -p1 -s < ../disable_custom_allocator.patch

[ -f Makefile ] || \
    ./configure --enable-zip
[ -f sapi/cli/php ] || \
    make -j`nproc`

# Execute the actual poc (add LD_PRELOAD here)
sapi/cli/php -f ../poc.php > ../poc-out.txt

if ! grep 'object(stdClass)#3 (0) refcount(1){' ../poc-out.txt >/dev/null; then echo "++++VULNERABLE++++"; else echo "not vulnerable"; fi

