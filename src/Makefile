C_SRC = mod_mrf.cpp
FILES = $(C_SRC)

DEFINES = -DLINUX -D_REENTRANT -D_GNU_SOURCE

# Create the ../Makefile.lcl, which should define
# APACHE_PATH, the root folder of the apache install
include Makefile.lcl
TARGET = .libs/mod_mrf.so

MOD_PATH=$(APACHE_PATH)/modules
INCLUDE= -I $(APACHE_PATH)/include

# Can't use apxs to build c++ modules
# The options used here might depend on how apache was built
$(TARGET)	:	$(FILES)
	libtool --silent --mode=compile g++ -prefer-pic -O2 -Wall $(DEFINES) $(INCLUDE) -pthread -c -o mod_mrf.lo $(C_SRC) && touch mod_mrf.slo
	libtool --silent --mode=link g++ -o mod_mrf.la -rpath $(MOD_PATH) -module -avoid-version mod_mrf.lo

install	: $(TARGET)
	cp $(TARGET) $(MOD_PATH)

clean	:
	rm -rf .libs *.{o,lo,slo,la}

