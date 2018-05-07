# Makefile for IKE

test: main.o libike.so
	gcc -o test main.o -L. -like -Wl,-rpath,. -lgmp -g

main.o: main.c
	gcc -c main.c -g

libike.so: ike.o hmac-sha1.o base64.o memxor.o sha1.o aes128.o
	gcc -shared -o libike.so -lgmp ike.o hmac-sha1.o base64.o memxor.o sha1.o aes128.o -g

ike.o: ike.c ike.h dh_protocol.c definitions.h transforms.c mem_clean.c
	gcc -c -fPIC ike.c -lgmp -g

hmac-sha1.o: hmac/hmac-sha1.c
	gcc -c -fPIC hmac/hmac-sha1.c -g

base64.o: hmac/base64.c
	gcc -c -fPIC hmac/base64.c -g

memxor.o: hmac/memxor.c
	gcc -c -fPIC hmac/memxor.c -g

sha1.o: hmac/sha1.c
	gcc -c -fPIC hmac/sha1.c -g

aes128.o: crypt/aes128.c
	gcc -c -fPIC crypt/aes128.c -g

clean:
	rm -f *.o *.a *.so test
