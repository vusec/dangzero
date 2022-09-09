gcc hello.c -o hello
gcc -fPIC -shared -pthread -O2 -o wrap.so dz.c gc.c -ldl
/bin/cp hello /trusted/consume
/bin/cp wrap.so /trusted/wrap.so
LD_PRELOAD=/trusted/wrap.so /trusted/consume
