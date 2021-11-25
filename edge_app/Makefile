all: decrypt lib keyclient

OPTS = -g -Wall -Wno-pointer-sign
#INCLUDES=-I../ch06 -I../ch01 -I../ch02 -I../ch03 -I../ch04 -I../ch05 -I../ch07 -I../ch08
SOURCE_FILES=decry.c tls.c\
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
privkey.c\
rsa.c \
x509.c 
HEADER_FILES=tls.h\
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
privkey.h\
rsa.h

OBJECT_FILE=decry.o\
tls.o\
base64.o\
hex.o\
des.o\
rc4.o\
aes.o\
huge.o\
dsa.o\
md5.o\
sha.o\
hmac.o\
digest.o\
asn1.o\
prf.o\
file.o\
privkey.o\
rsa.o\
x509.o

decrypt:$(SOURCE_FILES) $(HEADER_FILES) 
	gcc -DTEST_DECRY  $(OPTS) -o decrypt $(SOURCE_FILES) -lm



keyclient :keyclient.cpp des.h des.c hex.c hex.h
	gcc  -g -Wall -c  $(SOURCE_FILES) 
	g++ -DTEST_CLIENT -g -Wall -c keyclient.cpp
	g++ -g -Wall -o keyclient keyclient.o $(OBJECT_FILE)
	
lib: libpcap.cpp $(SOURCE_FILES) $(HEADER_FILES) keyclient.cpp 
	gcc  -g -Wall -c  $(SOURCE_FILES) 
	g++ -Wall  -g -lpcap -c libpcap.cpp
	g++ -g -Wall -c keyclient.cpp
	g++ -Wall -lpcap -o last libpcap.o  keyclient.o $(OBJECT_FILE)