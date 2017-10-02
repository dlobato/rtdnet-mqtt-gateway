include config.mk

DIRS=src

.PHONY : all rtdnet-mqtt-gateway clean reallyclean test install uninstall dist sign copy

all : $(MAKE_ALL)

rtdnet-mqtt-gateway :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d}; done

clean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} clean; done
	
reallyclean : 
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} reallyclean; done
	
install : mosquitto
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} install; done

uninstall :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} uninstall; done