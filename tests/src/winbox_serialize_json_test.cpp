#include <gtest/gtest.h>

#include "winbox_message.hpp"

class WinTestSerializeJSON : public testing::Test
{
protected:

    virtual void SetUp()
    {
    }

    WinboxMessage test_message;
};

TEST_F(WinTestSerializeJSON, bool_test)
{
    test_message.add_boolean(0xff0008, true);
    test_message.add_boolean(0xff0007, false);
    EXPECT_STREQ("{bff0007:0,bff0008:1}", test_message.serialize_to_json().c_str());
}

TEST_F(WinTestSerializeJSON, u32_test)
{
    test_message.add_u32(0xbaddad, 8);
    EXPECT_STREQ("{ubaddad:8}", test_message.serialize_to_json().c_str());
}

TEST_F(WinTestSerializeJSON, u64_test)
{
    test_message.add_u64(0xbaddad, 0x0101010101010101ULL);
    EXPECT_STREQ("{qbaddad:72340172838076673}", test_message.serialize_to_json().c_str());
}

TEST_F(WinTestSerializeJSON, string_test)
{
    test_message.add_string(0xbaddad, "man");
    test_message.add_string(0xc0ffee, "you really");
    test_message.add_string(0xdead, "freak me out");
    EXPECT_STREQ("{sdead:'freak me out',sbaddad:'man',sc0ffee:'you really'}", test_message.serialize_to_json().c_str());
}

TEST_F(WinTestSerializeJSON, message_test)
{
    WinboxMessage msg;
    msg.add_boolean(0xbadfad, true);

    test_message.add_msg(0xbaddad, msg);
    EXPECT_STREQ("{mbaddad:{bbadfad:1}}", test_message.serialize_to_json().c_str());
}

TEST_F(WinTestSerializeJSON, bool_array_test)
{
    std::vector<bool> bool_array;
    bool_array.push_back(true);
    bool_array.push_back(false);

    test_message.add_boolean_array(0xff0007, bool_array);
    EXPECT_STREQ("{Bff0007:[1,0]}", test_message.serialize_to_json().c_str());
}

TEST_F(WinTestSerializeJSON, u32_array_test)
{
    std::vector<boost::uint32_t> u32_array;
    u32_array.push_back(8000);
    u32_array.push_back(5);

    test_message.add_u32_array(0xff0007, u32_array);
    EXPECT_STREQ("{Uff0007:[8000,5]}", test_message.serialize_to_json().c_str());
}

TEST_F(WinTestSerializeJSON, u64_array_test)
{
    std::vector<boost::uint64_t> u64_array;
    u64_array.push_back(0x0101010101010101ULL);
    u64_array.push_back(0);

    test_message.add_u64_array(0xff0007, u64_array);
    EXPECT_STREQ("{Qff0007:[72340172838076673,0]}", test_message.serialize_to_json().c_str());
}

TEST_F(WinTestSerializeJSON, string_array_test)
{
    std::vector<std::string> string_array;
    string_array.push_back("pat");
    string_array.push_back("should");
    string_array.push_back("play");
    string_array.push_back("the");
    string_array.push_back("drums.");
    test_message.add_string_array(0xc0ffee, string_array);

    EXPECT_STREQ("{Sc0ffee:['pat','should','play','the','drums.']}", test_message.serialize_to_json().c_str());
}

TEST_F(WinTestSerializeJSON, message_array_test)
{
    WinboxMessage msg1;
    msg1.add_boolean(0xbadfad, true);

    WinboxMessage msg2;
    msg2.add_string(0xbadfad, "caroling in ocean park");

    std::vector<WinboxMessage> msgs;
    msgs.push_back(msg1);
    msgs.push_back(msg2);

    test_message.add_msg_array(0xc0ffee, msgs);
    EXPECT_STREQ("{Mc0ffee:[{bbadfad:1},{sbadfad:'caroling in ocean park'}]}", test_message.serialize_to_json().c_str());
}

