obj-m += dangmod.o

all:
	make -C /lib/modules/4.0.0-kml/build M=$(PWD) modules

clean:
	make -C /lib/modules/4.0.0-kml/build M=$(PWD) clean
