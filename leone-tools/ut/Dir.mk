TOOLS_UT_SRCS = $(wildcard leone-tools/ut/*.cpp)
TOOLS_UT_OBJS = $(addprefix $(BUILD_DIR)/, $(patsubst %.cpp, %.obj, $(TOOLS_UT_SRCS)))

TOOLS_UT_INCLUDES = -I leone-tools/include \
                    -I $(GTEST)/include

$(TOOLS_UT_OBJS): $(BUILD_DIR)/%.obj: %.cpp
	mkdir -p $(dir $@)
	$(CPP) -MMD $(CPPFLAGS) $(TOOLS_UT_INCLUDES) -c $< -o $@

$(BUILD_DIR)/bin/leone_tools_ut: ut_check $(TOOLS_OBJS) $(TOOLS_UT_OBJS)
	mkdir -p $(dir $@)
	$(CPP) -MMD $(CPPFLAGS) $(filter-out ut_check,$^) \
		$(GTEST_A) $(LIB_PTHREAD) -o $@
	-$@
