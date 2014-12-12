INCLUDES=-I$(PWD)/src -I$(GTEST)/include -L$(GTEST)/lib/.libs -L$(PWD)/bin
LIBS=-lgtest -lhurl

all:
	g++ $(INCLUDES) -o $(ODIR)/ut ut_hurl_parse.cpp $(LIBS)
	$(PWD)/bin/ut
	
