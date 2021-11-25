all:  ssl_webserver  keyserver

OPTS = -g -Wall -Wno-pointer-sign

#privkey: privkey.c privkey.h file.c file.h ../ch01/base64.c ../ch01/base64.h ../ch02/hex.c ../ch02/hex.h ../ch02/des.c ../ch02/des.h ../ch03/huge.c ../ch03/huge.h ../ch03/rsa.c ../ch03/rsa.h ../ch04/digest.c ../ch04/digest.h ../ch04/md5.c ../ch04/md5.h ../ch04/sha.c ../ch04/sha.c ../ch05/asn1.c ../ch05/asn1.h
#	gcc -I../ch01 -I../ch02 -I../ch03 -I../ch05 -DTEST_PRIVKEY $(INCLUDES) $(OPTS) -o privkey privkey.c file.c ../ch01/base64.c ../ch02/hex.c ../ch02/des.c ../ch03/huge.c ../ch03/rsa.c ../ch04/digest.c ../ch04/md5.c ../ch04/sha.c ../ch05/asn1.c -lm

#INCLUDES=-I../ch01 -I../ch02 -I../ch03 -I../ch04 -I../ch06 -I../ch05  -I../ch08 -I../ch07
SOURCE_FILES=\
privkey.c \
file.c \
base64.c \
hex.c \
des.c \
rc4.c \
aes.c \
huge.c \
dsa.c \
md5.c \
sha.c \
hmac.c \
digest.c \
asn1.c \
prf.c \
x509.c \
rsa.c \
tls.c 
HEADER_FILES=privkey.h \
file.h \
base64.h \
hex.h \
des.h \
rc4.h \
aes.h \
dh.h\
huge.h \
dsa.h \
md5.h \
sha.h \
hmac.h \
digest.h \
asn1.h\
prf.h\
x509.h \
rsa.h \
tls.h
ssl_webserver: $(SOURCE_FILES) $(HEADER_FILES) ssl_webserver.c
	gcc  $(OPTS) -o ssl_webserver ssl_webserver.c $(SOURCE_FILES) -lm


keyserver :keyserver.cpp des.h des.c hex.c hex.h
	gcc -g -Wall -c des.c
	gcc -g -Wall -c hex.c
	g++ -g -Wall -c keyserver.cpp
	g++ -g -Wall -o keyserver keyserver.o des.o  hex.o
clean:
	rm -f privkey
	rm -f ssl_webserver
	rm -f core
	rm -f core.*
