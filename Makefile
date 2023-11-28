obj-m += driver.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod driver.ko
	gcc -g3 -O0 --std=c99 -fsanitize=address,undefined,leak ./client.c -o client

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo rmmod driver
	rm -r client