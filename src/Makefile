MODULE = mod_mrf
TARGET = .libs/$(MODULE).so
C_SRC = $(MODULE).cpp

DEFINES = -DLINUX -D_REENTRANT -D_GNU_SOURCE $(DEBUG)

# Create the ../Makefile.lcl, which should define
# DEST, the folder where the apache module should reside
# INCLUDES, the gcc include commands for httpd, apr headers
# LIBTOOL, DEBUG ...

include Makefile.lcl

# Can't use apxs to build c++ modules
# The options used here might depend on how apache was built

default	:	$(TARGET)

$(TARGET)       :       $(C_SRC)
	$(LIBTOOL) --silent --mode=compile g++ -prefer-pic -O2 -Wall $(DEFINES) $(EXTRA_INCLUDES) -pthread -c -o $(MODULE).lo $< && touch $(MODULE).slo
	$(LIBTOOL) --silent --mode=link g++ -o $(MODULE).la -rpath $(DEST) -module -avoid-version $(MODULE).lo

install : $(TARGET)
	$(SUDO) $(CP) $(TARGET) $(DEST)

clean   :
	$(RM) -r .libs *.{o,lo,slo,la}
