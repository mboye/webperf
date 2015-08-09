phantomjs: $(CACHE_DIR)/bin/phantomjs-$(PLATFORM)-$(ARCH)

$(CACHE_DIR)/bin/phantomjs: $(CACHE_DIR)/bin/phantomjs-$(PLATFORM)

$(CACHE_DIR)/bin/phantomjs-darwin-$(ARCH): PKG_DIR=phantomjs-1.9.2-macosx
$(CACHE_DIR)/bin/phantomjs-darwin-$(ARCH): PKG=$(PKG_DIR).zip
$(CACHE_DIR)/bin/phantomjs-darwin-$(ARCH): DECOMPRESS_CMD=unzip -q $(PKG)

$(CACHE_DIR)/bin/phantomjs-linux-$(ARCH): PKG_DIR=phantomjs-1.9.2-linux-$(ARCH)
$(CACHE_DIR)/bin/phantomjs-linux-$(ARCH): PKG=$(PKG_DIR).tar.bz2
$(CACHE_DIR)/bin/phantomjs-linux-$(ARCH): DECOMPRESS_CMD=tar -jxf $(PKG)

$(CACHE_DIR)/bin/phantomjs-$(PLATFORM)-$(ARCH):
	mkdir -p "$(CACHE_DIR)/bin"
	wget --quiet --continue -O "$(CACHE_DIR)/$(PKG)" \
		"https://phantomjs.googlecode.com/files/$(PKG)"
	cd "$(CACHE_DIR)" && $(DECOMPRESS_CMD)
	mv "$(CACHE_DIR)/$(PKG_DIR)/bin/phantomjs" \
		"$(CACHE_DIR)/bin/phantomjs-$(PLATFORM)-$(ARCH)"
	rm -rf "$(CACHE_DIR)/$(PKG_DIR)"
	rm -f "$(CACHE_DIR)/$(PKG)"
	ln -sf "phantomjs-$(PLATFORM)-$(ARCH)" "$(CACHE_DIR)/bin/phantomjs"
