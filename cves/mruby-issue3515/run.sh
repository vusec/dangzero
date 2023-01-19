[ -d mruby ] || \
    git clone https://github.com/mruby/mruby.git

cd mruby
git checkout -q 191ee25

[ -f bin/mruby ] ||
    rake

echo [+] Running mruby poc.rb ...
bin/mruby ../poc.rb
