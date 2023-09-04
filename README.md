# DangZero

This repository contains the source code for the CCS'22 paper "DangZero: Efficient Use-After-Free Detection via Direct Page Table Access" by Floris Gorter, Koen Koning, Herbert Bos and Cristiano Giuffrida.  
The paper is available for download [here](https://download.vusec.net/papers/dangzero_ccs22.pdf).

## Building & Running
### Compile the KML kernel
NOTE: (docker container takes about 25 GB disk space)
```shell
cd kml-image
bash build_kml.sh
```

### Obtain Ubuntu 20.04
```shell
cd ../
wget https://releases.ubuntu.com/20.04/ubuntu-20.04.5-desktop-amd64.iso
```

### Create VM
```shell
qemu-img create -f qcow2 ubuntu.img 60G
```

### Install Ubuntu
NOTE: these commands assume username 'u16'
```shell
qemu-system-x86_64 -cdrom ubuntu-20.04.4-desktop-amd64.iso -drive "file=ubuntu.img,format=qcow2" -enable-kvm -m 16G -smp 16
```

### Run Ubuntu
```shell
qemu-system-x86_64 -drive "file=ubuntu.img,format=qcow2" -enable-kvm -m 16G -smp 16 -cpu host -net nic -net user,hostfwd=tcp::1810-:22
```

### Move KML kernel to VM
On the Guest (VM):
```shell
apt-get install openssh-server
```
On the Host:
```
scp -P 1810 kml-image/linux-*.deb u16@localhost:~/
```
### Inside VM: Install Kernel
```shell
cd ~/
sudo dpkg -i linux-*.deb
```

### Update grub to auto-select KML kernel
When not using a GUI for the VM, edit `/etc/default/grub`:
```
GRUB_DEFAULT="1>4" # depends on menu entries of grub
#GRUB_TIMEOUT_STYLE=hidden # comment out
GRUB_TIMEOUT=2 # if you want to see menu entries with GUI
```

### Boot parameters
Some systems may require the following boot param for booting KML (for GUI/tty).  
edit `/etc/default/grub`:  
```
GRUB_CMDLINE_LINUX_DEFAULT="vga=normal"
# Add console=ttyS0 if you want to run without GUI
GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0 vga=normal"
# Add make-linux-fast-again for performance:
GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0 vga=normal noibrs noibpb nopti nospectre_v2 nospectre_v1 l1tf=off nospec_store_bypass_disable no_stf_barrier mds=off tsx=on tsx_async_abort=off mitigations=off"
```

### Run KML
Suggested flags for `-cpu host`: at least `-pdpe1gb` (for DangZero performance), `-avx,-f16c,-avx512f` in case the kernel crashes on boot, e.g.:
```shell
qemu-system-x86_64 -drive "file=ubuntu.img,format=qcow2" -enable-kvm -m 8G -smp 16 -cpu host,-avx,-f16c,-avx512f,-pdpe1gb -nographic -serial mon:stdio -net nic -net user,hostfwd=tcp::1810-:22
```

### Test KML
Create the /`trusted` directory (may need sudo).  
Create an example `test.c` file:
```c
#include <stdio.h>
#include <stdint.h>
void main(){
    uint64_t cs = 0;
    int ring;
    asm("mov %%cs, %0" : "=r" (cs));
    ring = (int)(cs&3);
    printf("running in ring %d\n", ring);
}
```
Run the program inside `/trusted` and outside. Expected output:  
```shell
$ gcc test.c -o test
$ /trusted/test
running in ring 0
$ /home/u16/test
running in ring 3
```

### Obtain glibc-2.31
```shell
cd /trusted/
mkdir glibc
cd glibc
wget https://ftp.gnu.org/gnu/glibc/glibc-2.31.tar.gz
tar -xf glibc-2.31.tar.gz
```

Move the glibc patch to the VM:
```shell
scp -P 1810 patchglibc.diff u16@localhost:/trusted/glibc/glibc-2.31/
```

```shell
cd /trusted/glibc/glibc-2.31
patch -i patchglibc.diff -p 1
mkdir build
cd build
sudo apt-get install bison gawk -y
../configure --prefix=/trusted/glibc/
make -j `nproc`
make install
```

### Install gcc-5 for kernel module 
The KML kernel requires an old gcc version for compatibility with the kernel module.  
```shell
echo -e "deb http://dk.archive.ubuntu.com/ubuntu/ xenial main\ndeb http://dk.archive.ubuntu.com/ubuntu/ xenial universe" | sudo tee -a /etc/apt/sources.list
sudo apt-get update
sudo apt install gcc-5
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-5 50
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 90
sudo update-alternatives --config gcc
# select gcc-5
```

### Install the kernel module
```shell
cd kmod
make
sudo insmod dangmod.ko
```

### Test DangZero
Make sure to select `gcc-9` again as primary gcc  
Make sure the DangZero git files also exist in the VM (e.g., `dz.c`)  
```shell
bash test.sh
```
