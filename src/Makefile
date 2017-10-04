include ../config.mk

.PHONY: all install uninstall reallyclean clean

all : rtdnet-mqtt-gateway rtdnet-status rtdnet-set-temp

rtdnet-mqtt-gateway : gateway.o gateway_config.o mosquitto_helper.o rtdnet.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${GATEWAY_LDFLAGS} ${GATEWAY_LIBS}

gateway.o : gateway.c
	${CROSS_COMPILE}${CC} -c $< -o $@ ${GATEWAY_CFLAGS}

gateway_config.o : gateway_config.c gateway_config.h
	${CROSS_COMPILE}${CC} -c $< -o $@ ${GATEWAY_CFLAGS}

mosquitto_helper.o : mosquitto_helper.c mosquitto_helper.h
	${CROSS_COMPILE}${CC} -c $< -o $@ ${GATEWAY_CFLAGS}

rtdnet.o : rtdnet.c
	${CROSS_COMPILE}${CC} -c $< -o $@ ${GATEWAY_CFLAGS}

rtdnet-status : status.o rtdnet.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${RTDNET_TOOLS_LDFLAGS} ${RTDNET_TOOLS_LIBS}

status.o : status.c
	${CROSS_COMPILE}${CC} -c $< -o $@ ${RTDNET_TOOLS_CFLAGS}

rtdnet-set-temp : settemp.o rtdnet.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${RTDNET_TOOLS_LDFLAGS} ${RTDNET_TOOLS_LIBS}

settemp.o : settemp.c
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
