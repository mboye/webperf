ut_check:
	$(if $(wildcard $(GMOCK)),,$(error Could not find Google Mock directory))
	$(if $(wildcard $(GTEST)),,$(error Could not find Google Test directory))
	$(if $(wildcard $(GMOCK_A)),,$(error Could not find libgmock.a))
	$(if $(wildcard $(GTEST_A)),,$(error Could not find libgtest.a))

.PHONY: ut_check
