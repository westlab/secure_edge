all: https

OPTS = -g -Wall -Wno-pointer-sign

#INCLUDES=-I../ch06 -I../ch01 -I../ch02 -I../ch03 -I../ch04 -I../ch05 -I../ch07
SOURCE_FILES=https.c \
tls.c \
rsa.c \
x509.c \
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
file.c \
privkey.c
HEADER_FILES=tls.h \
rsa.h \
base64.h \
hex.h \
des.h \
rc4.h \
aes.h \
huge.h \
dsa.h \
md5.h \
sha.h \
hmac.h \
digest.h \
asn1.h \
prf.h \
x509.h \
file.h \
privkey.h

https: $(SOURCE_FILES) $(HEADER_FILES)
	gcc $(OPTS) -o https $(SOURCE_FILES) -lm

clean:
	rm -f https
	rm -f core
	rm -f core.*
