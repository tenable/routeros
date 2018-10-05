#include <gtest/gtest.h>

#include "winbox_message.hpp"

class WinTestParse : public testing::Test
{
protected:

    virtual void SetUp()
    {
    }

    WinboxMessage test_message;
};

TEST_F(WinTestParse, bool_test)
{
    std::string true_bool("\x05\x00\xff\x01", 4);
    EXPECT_TRUE(test_message.parse_binary(true_bool));
    EXPECT_TRUE(test_message.get_boolean(0xff0005));

    std::string false_bool("\x06\x00\xff\x00", 4);
    EXPECT_TRUE(test_message.parse_binary(false_bool));
    EXPECT_FALSE(test_message.get_boolean(0xff0006));
}

TEST_F(WinTestParse, u32_test)
{
    std::string u32_short("\x01\x00\x00\x09\x4a", 5);
    EXPECT_TRUE(test_message.parse_binary(u32_short));
    EXPECT_EQ(0x4a, test_message.get_u32(1));

    std::string u32("\x01\x02\x00\x08\xaa\xbb\xcc\xdd", 8);
    EXPECT_TRUE(test_message.parse_binary(u32));
    EXPECT_EQ(0xddccbbaa, test_message.get_u32(0x201));
}

TEST_F(WinTestParse, u64_test)
{
    std::string u64("\x01\x00\x00\x10\xde\xc0\xad\x0b\xde\xc0\xad\x0b", 12);
    EXPECT_TRUE(test_message.parse_binary(u64));
    EXPECT_EQ(0x0badc0de0badc0deULL, test_message.get_u64(1));
}

TEST_F(WinTestParse, ip6_test)
{
    std::string u64("\xad\xdd\xba\x18\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", 20);
    EXPECT_TRUE(test_message.parse_binary(u64));

    boost::array<unsigned char, 16> ip6 = { { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x7, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 } };
    boost::array<unsigned char, 16> parsed(test_message.get_ip6(0xbaddad));
    EXPECT_EQ(0, memcmp(&ip6[0], &parsed[0], 16));
}

TEST_F(WinTestParse, string_test)
{
    std::string short_string("\x03\x00\xff\x21\x05hello", 10);
    EXPECT_TRUE(test_message.parse_binary(short_string));
    EXPECT_STREQ("hello", test_message.get_string(0xff0003).c_str());

    std::string long_string("\x04\x00\xff\x20\x00\x01", 6);
    std::string as;
    as.resize(0xff, 'a');
    as.push_back('b');
    long_string.append(as);

    EXPECT_TRUE(test_message.parse_binary(long_string));
    EXPECT_STREQ(as.c_str(), test_message.get_string(0xff0004).c_str());
}

TEST_F(WinTestParse, message_test)
{
    std::string short_message("\xad\xdd\xba\x29\x06M2\xad\xdf\xba\x01", 11);
    EXPECT_TRUE(test_message.parse_binary(short_message));

    WinboxMessage msg(test_message.get_msg(0xbaddad));
    EXPECT_TRUE(msg.get_boolean(0xbadfad));
}

TEST_F(WinTestParse, raw_test)
{
    std::string short_raw("\x03\x00\xff\x31\x05hello", 10);
    EXPECT_TRUE(test_message.parse_binary(short_raw));
    EXPECT_STREQ("hello", test_message.get_raw(0xff0003).c_str());

    std::string long_raw("\x04\x00\xff\x30\x00\x01", 6);
    std::string as;
    as.resize(0xff, 'a');
    as.push_back('b');
    long_raw.append(as);

    EXPECT_TRUE(test_message.parse_binary(long_raw));
    EXPECT_STREQ(as.c_str(), test_message.get_raw(0xff0004).c_str());
}

TEST_F(WinTestParse, bool_array_test)
{
    std::string bool_array("\xad\xdd\xba\x80\x03\x00\x01\x00\x01", 10);
    EXPECT_TRUE(test_message.parse_binary(bool_array));
    ASSERT_EQ(3, test_message.get_boolean_array(0xbaddad).size());
    EXPECT_TRUE(test_message.get_boolean_array(0xbaddad)[0]);
    EXPECT_FALSE(test_message.get_boolean_array(0xbaddad)[1]);
    EXPECT_TRUE(test_message.get_boolean_array(0xbaddad)[2]);
}

TEST_F(WinTestParse, u32_array_test)
{
    std::string empty_array("\x0a\x0b\x0c\x88\x00\x00", 6);
    EXPECT_TRUE(test_message.parse_binary(empty_array));
    EXPECT_TRUE(test_message.get_u32_array(0xc0b0a).empty());

    std::string one_array("\x0b\x0b\x0c\x88\x01\x00\x0a\x0b\x0c\x0d", 10);
    EXPECT_TRUE(test_message.parse_binary(one_array));
    ASSERT_EQ(1, test_message.get_u32_array(0xc0b0b).size());
    EXPECT_EQ(0x0d0c0b0a, test_message.get_u32_array(0xc0b0b)[0]);
}

TEST_F(WinTestParse, u64_array_test)
{
    std::string u64_array("\xad\xdd\xba\x90\x02\x00\x08\x07\x06\x05\x04\x03\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00", 22);
    EXPECT_TRUE(test_message.parse_binary(u64_array));
    ASSERT_EQ(2, test_message.get_u64_array(0xbaddad).size());
    EXPECT_EQ(0x0102030405060708ULL, test_message.get_u64_array(0xbaddad)[0]);
    EXPECT_EQ(1, test_message.get_u64_array(0xbaddad)[1]);
}

TEST_F(WinTestParse, ip6_array_test)
{
    std::string ip6_array("\xad\xdd\xba\x98\x01\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", 22);
    EXPECT_TRUE(test_message.parse_binary(ip6_array));
    ASSERT_EQ(1, test_message.get_ip6_array(0xbaddad).size());

    boost::array<unsigned char, 16> ip6 = { { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 } };
    EXPECT_EQ(0, memcmp(&ip6[0], &test_message.get_ip6_array(0xbaddad)[0][0], 16));
}

TEST_F(WinTestParse, string_array_test)
{
    std::string string_array("\xad\xdd\xba\xa0\x03\x00\x05\x00shred\x03\x00the\x05\x00\x63\x65\x6c\x6c\x6f", 25);
    EXPECT_TRUE(test_message.parse_binary(string_array));
    ASSERT_EQ(3, test_message.get_string_array(0xbaddad).size());

    EXPECT_STREQ("shred", test_message.get_string_array(0xbaddad)[0].c_str());
    EXPECT_STREQ("the", test_message.get_string_array(0xbaddad)[1].c_str());
    EXPECT_STREQ("cello", test_message.get_string_array(0xbaddad)[2].c_str());
}

TEST_F(WinTestParse, message_array_test)
{
    std::string string_array("\xad\xdd\xba\xa8\x02\x00\x06\x00M2\xad\xdf\xba\x01\x07\x00M2\xad\xdf\xba\x09\x01", 23);
    EXPECT_TRUE(test_message.parse_binary(string_array));
    ASSERT_EQ(2, test_message.get_msg_array(0xbaddad).size());
    EXPECT_TRUE(test_message.get_msg_array(0xbaddad)[0].get_boolean(0xbadfad));
    EXPECT_EQ(1, test_message.get_msg_array(0xbaddad)[1].get_u32(0xbadfad));
}

TEST_F(WinTestParse, raw_array_test)
{
    std::string raw_array("\xad\xdd\xba\xb0\x02\x00\x03\x00i'm\x05\x00jello", 18);
    EXPECT_TRUE(test_message.parse_binary(raw_array));
    ASSERT_EQ(2, test_message.get_raw_array(0xbaddad).size());

    EXPECT_STREQ("i'm", test_message.get_raw_array(0xbaddad)[0].c_str());
    EXPECT_STREQ("jello", test_message.get_raw_array(0xbaddad)[1].c_str());
}
