CC = gcc
CFLAGS	= -Wall -g -D_GNU_SOURCE 


%.o: %.c
	$(CC) -c $< $(CFLAGS)

all: sandbox.so
sandbox.so: sandbox.c
	$(CC) -o sandbox.so -shared  -fPIC -ldl sandbox.c
# test: test_1 test_2 test_3
# test_1:
# 	./launcher  ./sandbox.so  config.txt   cat /etc/passwd
# test_2:
# 	./launcher ./sandbox.so config.txt cat /etc/hosts
# test_3:
# 	./launcher ./sandbox.so config.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem


clean : 
	rm -f *.o *.so