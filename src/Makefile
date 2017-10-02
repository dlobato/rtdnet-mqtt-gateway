include ../config.mk

.PHONY: all install uninstall reallyclean clean

all : rtdnet-mqtt-gateway rtdnet-status rtdnet-set-temp

rtdnet-mqtt-gateway : rtdnet-mqtt-gateway.o client_shared.o rtdnet.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${GATEWAY_LDFLAGS} ${GATEWAY_LIBS}

rtdnet-mqtt-gateway.o : rtdnet-mqtt-gateway.c
	${CROSS_COMPILE}${CC} -c $< -o $@ ${GATEWAY_CFLAGS}

client_shared.o : client_shared.c client_shared.h
	${CROSS_COMPILE}${CC} -c $< -o $@ ${GATEWAY_CFLAGS}

rtdnet.o : rtdnet.c
	${CROSS_COMPILE}${CC} -c $< -o $@ ${GATEWAY_CFLAGS}

rtdnet-status : rtdnet-status.o rtdnet.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${RTDNET_TOOLS_LDFLAGS} ${RTDNET_TOOLS_LIBS}

rtdnet-status.o : rtdnet-status.c
	${CROSS_COMPILE}${CC} -c $< -o $@ ${RTDNET_TOOLS_CFLAGS}

rtdnet-set-temp : rtdnet-set-temp.o rtdnet.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${RTDNET_TOOLS_LDFLAGS} ${RTDNET_TOOLS_LIBS}

rtdnet-set-temp.o : rtdnet-set-temp.c
	${CROSS_COMPILE}${CC} -c $< -o $@ ${RTDNET_TOOLS_CFLAGS}

install : all
	$(INSTALL) -d ${DESTDIR}$(prefix)/bin
	$(INSTALL) -s --strip-program=${CROSS_COMPILE}${STRIP} rtdnet-mqtt-gateway ${DESTDIR}${prefix}/bin/rtdnet-mqtt-gateway
	$(INSTALL) -s --strip-program=${CROSS_COMPILE}${STRIP} rtdnet-mqtt-gateway ${DESTDIR}${prefix}/bin/rtdnet-status
	$(INSTALL) -s --strip-program=${CROSS_COMPILE}${STRIP} rtdnet-mqtt-gateway ${DESTDIR}${prefix}/bin/rtdnet-set-temp

uninstall :
	-rm -f ${DESTDIR}${prefix}/bin/rtdnet-mqtt-gateway
	-rm -f ${DESTDIR}${prefix}/bin/rtdnet-status
	-rm -f ${DESTDIR}${prefix}/bin/rtdnet-set-temp

reallyclean : clean

clean : 
	-rm -f *.o rtdnet-mqtt-gateway rtdnet-status rtdnet-set-temp
