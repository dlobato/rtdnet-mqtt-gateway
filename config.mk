VERSION=0.0.1
TIMESTAMP:=$(shell date "+%F %T%z")

UNAME:=$(shell uname -s)

CFLAGS?=-Wall -ggdb -O2 -Wno-unused-result

GATEWAY_LIBS:= -lmosquitto -lmodbus -ljson-c
GATEWAY_CFLAGS:=${CFLAGS} ${CPPFLAGS} -DVERSION="\"${VERSION}\"" -D_GNU_SOURCE -DWITH_TLS -DWITH_TLS_PSK 
GATEWAY_LDFLAGS:=$(LDFLAGS)

RTDNET_TOOLS_LIBS:= -lmodbus
RTDNET_TOOLS_CFLAGS:=${CFLAGS} ${CPPFLAGS} -DVERSION="\"${VERSION}\""
RTDNET_TOOLS_LDFLAGS:=$(LDFLAGS)

MAKE_ALL:=rtdnet-mqtt-gateway

INSTALL?=install
prefix=/usr/local
mandir=${prefix}/share/man
localedir=${prefix}/share/locale
STRIP?=strip
