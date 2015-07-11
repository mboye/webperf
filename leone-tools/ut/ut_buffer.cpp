#include <gtest/gtest.h>
#include <string.h>
#include <stdlib.h>

extern "C" {
}

TEST(Buffer, InitializeBuffer)
{
    EXPECT_EQ(0, 1);
}


int main(int argc,
         char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
