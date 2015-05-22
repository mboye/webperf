export GMOCK=gmock-1.7.0
export GTEST=gmock-1.7.0/gtest
INCLUDES=-I../include -I$(GTEST)/include -L$(GTEST)/lib/.libs
LIBS=-lgtest -lhurl

all: build

build:
	g++ $(INCLUDES) -o $(ODIR)/ut ut_hurl_parse.cpp $(LIBS)
	
setup: FORCE
	test -d $(GMOCK) || \
		(wget -c "https://googlemock.googlecode.com/files/gmock-1.7.0.zip" && \
		unzip gmock-1.7.0.zip)
	test -d $(GMOCK) 
	test -d $(GTEST)
	cd $(GTEST) && ./configure && make && cd ..
	test -f $(GTEST)/lib/libgtest.la
	cd $(GMOCK) && ./configure && make && cd ..
	test -f $(GMOCK)/lib/libgmock.la
FORCE:

