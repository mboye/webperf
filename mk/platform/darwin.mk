override CFLAGS += -Wno-deprecated-declarations

ut_setup:
	test ! -d gmock-1.7.0
	wget -c https://googlemock.googlecode.com/files/gmock-1.7.0.zip
	unzip gmock-1.7.0.zip
	cd gmock-1.7.0 && \
		./configure CXX="clang++ -std=c++11 -stdlib=libc++ -DGTEST_USE_OWN_TR1_TUPLE=1" && \
			make

.PHONY: ut_setup
