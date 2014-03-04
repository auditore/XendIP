#configureable stuff
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
LIBDIR ?= $(PREFIX)/lib/XendIp
#For most systems, this works
INSTALL ?= install
#For Solaris, you may need
#INSTALL=/usr/ucb/install

CFLAGS=	-fPIC -fsigned-char -g -pipe -Wall -Wpointer-arith -Wwrite-strings \
			-Wstrict-prototypes -Wnested-externs -Winline  -g -Wcast-align \
			-DSENDIP_LIBS=\"$(LIBDIR)\" -I/usr/include -I /usr/include/libxml2/ -L /usr/lib/ 
#-Wcast-align causes problems on solaris, but not serious ones
LDFLAGS=	-g -rdynamic -lm
#LDFLAGS_SOLARIS= -g -lsocket -lnsl -lm
LDFLAGS_SOLARIS= -g -lsocket -lnsl -lm -ldl
LDFLAGS_LINUX= -g  -rdynamic -ldl -lm  -lxml2 -lz
LIBCFLAGS= -shared
CC=	gcc

PROGS= XendIp
BASEPROTOS= ipv4.so ipv6.so
IPPROTOS= icmp.so tcp.so udp.so
UDPPROTOS= rip.so ripng.so ntp.so
TCPPROTOS= bgp.so
PROTOS= $(BASEPROTOS) $(IPPROTOS) $(UDPPROTOS) $(TCPPROTOS)
GLOBALOBJS= csum.o compact.o

all:	$(GLOBALOBJS) XendIp $(PROTOS) XendIp.1 XendIp.spec

#there has to be a nice way to do this
XendIp:	XendIp.o	gnugetopt.o gnugetopt1.o compact.o XmlParser.o
	sh -c "if [ `uname` = Linux ] ; then \
$(CC)   $(CFLAGS) $+ $(LDFLAGS_LINUX) -o $@; \
elif [ `uname` = SunOS ] ; then \
$(CC) -o $@ $(LDFLAGS_SOLARIS) $(CFLAGS) $+ ;\
else \
$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $+ ; \
fi"

XendIp.1:	./help2man $(PROGS) $(PROTOS) VERSION
			./help2man -n "Send arbitrary IP packets" -N >XendIp.1

XendIp.spec:	XendIp.spec.in VERSION
			echo -n '%define ver ' >XendIp.spec
			cat VERSION >>XendIp.spec
			cat XendIp.spec.in >>XendIp.spec

%.so: %.c $(GLOBALOBJS)
			$(CC) -o $@ $(CFLAGS) $(LIBCFLAGS) $+

.PHONY:	clean install

clean:
			rm -f *.o *~ *.so $(PROTOS) $(PROGS) core gmon.out

veryclean:
			make clean
			rm -f XendIp.spec XendIp.1

install:		all
			[ -d $(LIBDIR) ] || mkdir -p $(LIBDIR)
			[ -d $(BINDIR) ] || mkdir -p $(BINDIR)
			[ -d $(MANDIR) ] || mkdir -p $(MANDIR)
			$(INSTALL) -m 755 $(PROGS) $(BINDIR)
			$(INSTALL) -m 644 XendIp.1 $(MANDIR)
			$(INSTALL) -m 755 $(PROTOS) $(LIBDIR)



