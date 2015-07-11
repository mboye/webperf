LIB_PTHREAD = -pthread

ut_setup:
	test ! -d gmock-1.7.0
	wget -c https://googlemock.googlecode.com/files/gmock-1.7.0.zip
	unzip gmock-1.7.0.zip
	cd gmock-1.7.0 && ./configure && make

.PHONY: ut_setup
