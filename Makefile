sslv=$(firstword $(wildcard $(addsuffix /include/openssl/opensslv.h,/usr/local /opt/local $(wildcard /usr/local/opt/openssl*) /usr)))
dirname=$(dir $(patsubst %/,%,$1))
OPENSSLDIR=$(call dirname,$(call dirname,$(call dirname,$(sslv))))


CXXFLAGS+= -std=c++1z -D_USE_OPENSSL
CXXFLAGS+=-g -Wall -c $(if $(D),-O0,-O3) -I cpputils -I dumputils -D_UNIX -D_NO_RAPI  -I /usr/local/include -I$(OPENSSLDIR)/include
LDFLAGS+=-g -Wall -L/usr/local/lib -L$(OPENSSLDIR)/lib

all: dump dump2 mmedit mmdump

# test for macos
ifneq ($(wildcard /System/Library/Extensions),)
OSTYPE=Darwin
endif

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
	$(RM) -r build CMakeFiles CMakeCache.txt CMakeOutput.log

install: dump
	cp dump ~/bin

cmake:
	cmake -B build . $(if $(D),-DCMAKE_BUILD_TYPE=Debug,-DCMAKE_BUILD_TYPE=Release) $(CMAKEARGS)
	$(MAKE) -C build $(if $(V),VERBOSE=1)

vc:
	"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe" -G"Visual Studio 16 2019" -B build .
	"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin/amd64/MSBuild.exe" build/cpputils.sln -t:Rebuild


