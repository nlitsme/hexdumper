sslv=$(firstword $(wildcard $(addsuffix /include/openssl/opensslv.h,/usr/local /opt/local $(wildcard /usr/local/opt/openssl*) /usr)))
dirname=$(dir $(patsubst %/,%,$1))
OPENSSLDIR=$(call dirname,$(call dirname,$(call dirname,$(sslv))))


CXXFLAGS+= -std=c++1z -D_USE_OPENSSL
CXXFLAGS+=-g -Wall -c $(if $(D),-O0,-O3) -I cpputils -I dumputils -D_UNIX -D_NO_RAPI  -I /usr/local/include -I$(OPENSSLDIR)/include
LDFLAGS+=-g -Wall -L/usr/local/lib -L$(OPENSSLDIR)/lib

all: dump dump2 mmedit mmdump

dump: dump.o bighexdump.o bigascdump.o
dump2: dump2.o  $(if $(filter $(OSTYPE),Darwin),machmemory.o)
mmdump: mmdump.o
mmedit: mmedit.o

LDFLAGS+=-lcrypto
ifeq ($(OSTYPE),Darwin)
LDFLAGS+=-framework Security
endif

%.o: dumputils/%.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ 
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(filter %.cpp,$^) -o $@  $(cflags_$(basename $(notdir $@)))

%: %.o
	$(CXX) $^ -o $@ $(foreach i,$^,$(ldflags_$(basename $(notdir $i)))) $(exeflags_$(basename $(notdir $@)))  $(LDFLAGS)

clean:
	$(RM) -r a.out* $(wildcard *.o *.dSYM) dump dump2

install: dump
	cp dump ~/bin

