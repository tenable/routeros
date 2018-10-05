#include <gtest/gtest.h>

#include "winbox_message.hpp"

class WinTestSerializeBinary : public testing::Test
{
protected:

    virtual void SetUp()
    {
    }

    WinboxMessage test_message;
};

TEST_F(WinTestSerializeBinary, bool_test)
{
    test_message.add_boolean(0xbaddad, true);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(4, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\x01", 4));
}

TEST_F(WinTestSerializeBinary, u32_test)
{
    test_message.add_u32(0xbaddad, 8);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(5, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\x09\x08", 5));

    test_message.reset();

    test_message.add_u32(0xbaddad, 0xc0ffee);
    std::string serialized_long(test_message.serialize_to_binary());

    ASSERT_EQ(8, serialized_long.size());
    ASSERT_EQ(0, memcmp(serialized_long.data(), "\xad\xdd\xba\x08\xee\xff\xc0\x00", 8));
}

TEST_F(WinTestSerializeBinary, u64_test)
{
    boost::uint64_t val = 0x0badc0de0badc0deULL;
    test_message.add_u64(0xbaddad, val);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(12, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\x10\xde\xc0\xad\x0b\xde\xc0\xad\x0b", 12));
}

TEST_F(WinTestSerializeBinary, ip6_test)
{
    boost::array<unsigned char, 16> ip6 = { { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x7, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 } };

    test_message.add_ip6(0xbaddad, ip6);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(20, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\x18\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", 20));
}

TEST_F(WinTestSerializeBinary, string_test)
{
    test_message.add_string(0xbaddad, "lolwat");
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(11, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\x21\x06lolwat", 11));

    test_message.reset();

    std::string long_string;
    long_string.resize(0x102, 'a');
    test_message.add_string(0xbaddad, long_string);
    std::string serialized_long(test_message.serialize_to_binary());

    ASSERT_EQ(0x108, serialized_long.size());
    EXPECT_EQ(0x20, serialized_long[3]);
    EXPECT_EQ(0x02, serialized_long[4]);
    EXPECT_EQ(0x01, serialized_long[5]);
    EXPECT_STREQ(long_string.c_str(), &serialized_long[6]);
}

TEST_F(WinTestSerializeBinary, raw_test)
{
    test_message.add_raw(0xbaddad, "lolwat");
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(11, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\x31\x06lolwat", 11));

    test_message.reset();

    std::string long_string;
    long_string.resize(0x102, 'a');
    test_message.add_string(0xbaddad, long_string);
    std::string serialized_long(test_message.serialize_to_binary());

    ASSERT_EQ(0x108, serialized_long.size());
    EXPECT_EQ(0x20, serialized_long[3]);
    EXPECT_EQ(0x02, serialized_long[4]);
    EXPECT_EQ(0x01, serialized_long[5]);
    EXPECT_STREQ(long_string.c_str(), &serialized_long[6]);
}

TEST_F(WinTestSerializeBinary, message_test)
{
    WinboxMessage msg;
    msg.add_boolean(0xbadfad, true);

    test_message.add_msg(0xbaddad, msg);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(9, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\x29\x04\xad\xdf\xba\x01", 9));

    test_message.reset();
    msg.reset();

    std::string long_string;
    long_string.resize(0x102, 'a');
    msg.add_string(0xbaddad, long_string);
    test_message.add_msg(0xbaddad, msg);
    std::string serialized_long(test_message.serialize_to_binary());

    ASSERT_EQ(0x10e, serialized_long.size());
    ASSERT_EQ(0, memcmp(serialized_long.data(), "\xad\xdd\xba\x28\x08\x01", 6));
    EXPECT_EQ(0x20, serialized_long[9]);
    EXPECT_EQ(0x02, serialized_long[10]);
    EXPECT_EQ(0x01, serialized_long[11]);
    EXPECT_STREQ(long_string.c_str(), &serialized_long[12]);
}

TEST_F(WinTestSerializeBinary, bool_array_test)
{
    std::vector<bool> bool_array;
    bool_array.push_back(true);
    bool_array.push_back(false);
    bool_array.push_back(true);

    test_message.add_boolean_array(0xbaddad, bool_array);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(9, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\x80\x03\x00\x01\x00\x01", 9));
}

TEST_F(WinTestSerializeBinary, u32_array_test)
{
    std::vector<boost::uint32_t> u32_array;
    u32_array.push_back(0xff0033);
    u32_array.push_back(1);

    test_message.add_u32_array(0xbaddad, u32_array);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(14, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\x88\x02\x00\x33\x00\xff\x00\x01\x00\x00\x00", 14));
}

TEST_F(WinTestSerializeBinary, u64_array_test)
{
    std::vector<boost::uint64_t> u64_array;
    u64_array.push_back(0x0102030405060708ULL);
    u64_array.push_back(1);

    test_message.add_u64_array(0xbaddad, u64_array);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(22, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\x90\x02\x00\x08\x07\x06\x05\x04\x03\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00", 22));
}

TEST_F(WinTestSerializeBinary, ip6_array_test)
{
    boost::array<unsigned char, 16> ip6 = { { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 } };
    std::vector<boost::array<unsigned char, 16> > ip6_array;
    ip6_array.push_back(ip6);

    test_message.add_ip6_array(0xbaddad, ip6_array);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(22, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\x98\x01\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", 22));
}

TEST_F(WinTestSerializeBinary, string_array_test)
{
    std::vector<std::string> string_array;
    string_array.push_back("shred");
    string_array.push_back("the");
    string_array.push_back("cello");

    test_message.add_string_array(0xbaddad, string_array);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(25, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\xa0\x03\x00\x05\x00shred\x03\x00the\x05\x00\x63\x65\x6c\x6c\x6f", 25));
}

TEST_F(WinTestSerializeBinary, message_array_test)
{
    WinboxMessage bool_msg;
    bool_msg.add_boolean(0xbadfad, true);

    WinboxMessage u32_msg;
    u32_msg.add_u32(0xbadfad, 1);

    std::vector<WinboxMessage> msgs;
    msgs.push_back(bool_msg);
    msgs.push_back(u32_msg);

    test_message.add_msg_array(0xbaddad, msgs);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(19, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\xa8\x02\x00\x04\x00\xad\xdf\xba\x01\x05\x00\xad\xdf\xba\x09\x01", 19));
}

TEST_F(WinTestSerializeBinary, raw_array_test)
{
    std::vector<std::string> string_array;
    string_array.push_back("i'm");
    string_array.push_back("jello");

    test_message.add_raw_array(0xbaddad, string_array);
    std::string serialized(test_message.serialize_to_binary());

    ASSERT_EQ(18, serialized.size());
    ASSERT_EQ(0, memcmp(serialized.data(), "\xad\xdd\xba\xb0\x02\x00\x03\x00i'm\x05\x00jello", 18));
}
