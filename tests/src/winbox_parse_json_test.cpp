#include <gtest/gtest.h>

#include "winbox_message.hpp"

class WinTestParseJSON : public testing::Test
{
protected:

    virtual void SetUp()
    {
    }

    WinboxMessage test_message;
};

TEST_F(WinTestParseJSON, bool_test)
{
   ASSERT_TRUE(test_message.parse_json("{bff0007:0,bff0008:1}"));
   EXPECT_FALSE(test_message.get_boolean(0xff0007));
   EXPECT_TRUE(test_message.get_boolean(0xff0008));
}

TEST_F(WinTestParseJSON, u32_test)
{
    ASSERT_TRUE(test_message.parse_json("{ubaddad:8,uc0ffee:8888}"));
    EXPECT_EQ(8, test_message.get_u32(0xbaddad));
    EXPECT_EQ(8888, test_message.get_u32(0xc0ffee));
}

TEST_F(WinTestParseJSON, u64_test)
{
    ASSERT_TRUE(test_message.parse_json("{qbaddad:1,qc0ffee:72340172838076673}"));
    EXPECT_EQ(1, test_message.get_u64(0xbaddad));
    EXPECT_EQ(72340172838076673, test_message.get_u64(0xc0ffee));
}

TEST_F(WinTestParseJSON, string_test)
{
    ASSERT_TRUE(test_message.parse_json("{sdead:'back to',sbaddad:'the',sc0ffee:'good life'}"));
    EXPECT_STREQ("back to", test_message.get_string(0xdead).c_str());
    EXPECT_STREQ("the", test_message.get_string(0xbaddad).c_str());
    EXPECT_STREQ("good life", test_message.get_string(0xc0ffee).c_str());
}

TEST_F(WinTestParseJSON, message_test)
{
    ASSERT_TRUE(test_message.parse_json("{mbaddad:{bbadfad:1,u1:1}}"));
    WinboxMessage stored(test_message.get_msg(0xbaddad));

    EXPECT_TRUE(stored.get_boolean(0xbadfad));
    EXPECT_EQ(1, stored.get_u32(1));
}

TEST_F(WinTestParseJSON, bool_array_test)
{
    ASSERT_TRUE(test_message.parse_json("{Bff0007:[1,0]}"));
    ASSERT_EQ(2, test_message.get_boolean_array(0xff0007).size());
    EXPECT_TRUE(test_message.get_boolean_array(0xff0007)[0]);
    EXPECT_FALSE(test_message.get_boolean_array(0xff0007)[1]);
}

TEST_F(WinTestParseJSON, u32_array_test)
{
    ASSERT_TRUE(test_message.parse_json("{Uff0007:[8000,5]}"));
    ASSERT_EQ(2, test_message.get_u32_array(0xff0007).size());
    EXPECT_EQ(8000, test_message.get_u32_array(0xff0007)[0]);
    EXPECT_EQ(5, test_message.get_u32_array(0xff0007)[1]);
}

TEST_F(WinTestParseJSON, u64_array_test)
{
    ASSERT_TRUE(test_message.parse_json("{Qff0007:[72340172838076673,0]}"));
    ASSERT_EQ(2, test_message.get_u64_array(0xff0007).size());
    EXPECT_EQ(72340172838076673, test_message.get_u64_array(0xff0007)[0]);
    EXPECT_EQ(0, test_message.get_u64_array(0xff0007)[1]);
}

TEST_F(WinTestParseJSON, string_array_test)
{
    ASSERT_TRUE(test_message.parse_json("{Sc0ffee:['the','world','has','turned']}"));
    ASSERT_EQ(4, test_message.get_string_array(0xc0ffee).size());
    EXPECT_STREQ("the", test_message.get_string_array(0xc0ffee)[0].c_str());
    EXPECT_STREQ("world", test_message.get_string_array(0xc0ffee)[1].c_str());
    EXPECT_STREQ("has", test_message.get_string_array(0xc0ffee)[2].c_str());
    EXPECT_STREQ("turned", test_message.get_string_array(0xc0ffee)[3].c_str());
}

TEST_F(WinTestParseJSON, message_array_test)
{
    ASSERT_TRUE(test_message.parse_json("{Mc0ffee:[{bbadfad:1},{sbadfad:'no one hears me sing this song'}]}"));
    ASSERT_EQ(2, test_message.get_msg_array(0xc0ffee).size());
    EXPECT_TRUE(test_message.get_msg_array(0xc0ffee)[0].get_boolean(0xbadfad));
    EXPECT_STREQ("no one hears me sing this song", test_message.get_msg_array(0xc0ffee)[1].get_string(0xbadfad).c_str());
}

