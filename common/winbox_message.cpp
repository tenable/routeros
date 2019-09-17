#include "winbox_message.hpp"

#include <regex>
#include <cstring>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>

namespace
{
    namespace variable_type
    {
        const boost::uint32_t k_bool = 0;
        const boost::uint32_t k_short_length = 0x01000000;
        const boost::uint32_t k_u32 = 0x08000000;
        const boost::uint32_t k_u64 = 0x10000000;
        const boost::uint32_t k_ip6 = 0x18000000;
        const boost::uint32_t k_string = 0x20000000;
        const boost::uint32_t k_message = 0x28000000;
        const boost::uint32_t k_raw = 0x30000000;
        const boost::uint32_t k_bool_array = 0x80000000;
        const boost::uint32_t k_u32_array = 0x88000000;
        const boost::uint32_t k_u64_array = 0x90000000;
        const boost::uint32_t k_ip6_array = 0x98000000;
        const boost::uint32_t k_string_array = 0xa0000000;
        const boost::uint32_t k_message_array = 0xa8000000;
        const boost::uint32_t k_raw_array = 0xb0000000;
    }

    namespace variable_names
    {
        const boost::uint32_t k_sys_to = 0x00ff0001;
        const boost::uint32_t k_from = 0x00ff0002;
        const boost::uint32_t k_reply_expected = 0x00ff0005;
        const boost::uint32_t k_request_id = 0x00ff0006;
        const boost::uint32_t k_command = 0x00ff0007;
        const boost::uint32_t k_error_code = 0x00ff0008;
        const boost::uint32_t k_error_string = 0x00ff0009;
        const boost::uint32_t k_session_id = 0x00fe0001;
    }

    namespace error_codes
    {
        const boost::uint32_t k_not_implemented = 0x00fe0002;
        const boost::uint32_t k_not_implementedv2 = 0x00fe0003;
        const boost::uint32_t k_obj_nonexistant = 0x00fe0004;
        const boost::uint32_t k_not_permitted = 0x00fe0009;
        const boost::uint32_t k_timeout = 0x00fe000d;
        const boost::uint32_t k_obj_nonexistant2 = 0x00fe0011;
        const boost::uint32_t k_busy = 0x00fe0012;
    }

    void do_comma(std::stringstream& p_json, bool& p_first)
    {
        if (!p_first)
        {
            p_json << ",";
        }
        else
        {
            p_first = false;
        }
    }
}

WinboxMessage::WinboxMessage() :
    m_bools(),
    m_u32s(),
    m_u64s(),
    m_ip6s(),
    m_strings(),
    m_msgs(),
    m_raw(),
    m_bool_array(),
    m_u32_array(),
    m_u64_array(),
    m_ip6_array(),
    m_string_array(),
    m_msg_array(),
    m_raw_array()
{
}

WinboxMessage::~WinboxMessage()
{
}

void WinboxMessage::reset()
{
    m_bools.clear();
    m_u32s.clear();
    m_u64s.clear();
    m_ip6s.clear();
    m_strings.clear();
    m_msgs.clear();
    m_raw.clear();
    m_bool_array.clear();
    m_u32_array.clear();
    m_u64_array.clear();
    m_ip6_array.clear();
    m_string_array.clear();
    m_msg_array.clear();
    m_raw_array.clear();
}

std::string WinboxMessage::serialize_to_binary() const
{
    std::string return_val;

    for (std::map<boost::uint32_t, bool>::const_iterator it = m_bools.begin();
         it != m_bools.end(); ++it)
    {
        std::string command;
        command.resize(4);

        boost::uint32_t type = it->first;
        if (it->second)
        {
            type |= variable_type::k_short_length;
        }

        memcpy(&command[0], &type, sizeof(type));
        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, boost::uint32_t>::const_iterator it = m_u32s.begin();
         it != m_u32s.end(); ++it)
    {
        std::string command;
        boost::uint32_t type = variable_type::k_u32 | it->first;
        boost::uint32_t value = it->second;

        if (value > 255)
        {
            // two byte length
            command.resize(sizeof(type) + sizeof(value));
            memcpy(&command[0], &type, sizeof(type));
            memcpy(&command[4], &value, sizeof(value));
        }
        else
        {
            // one byte length
            type |= variable_type::k_short_length;
            command.resize(sizeof(type) + 1);
            memcpy(&command[0], &type, sizeof(type));
            command[4] = value & 0xff;
        }

        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, boost::uint64_t>::const_iterator it = m_u64s.begin();
         it != m_u64s.end(); ++it)
    {
        std::string command;
        boost::uint32_t type = variable_type::k_u64 | it->first;
        boost::uint64_t value = it->second;

        command.resize(sizeof(type) + sizeof(value));
        memcpy(&command[0], &type, sizeof(type));
        memcpy(&command[4], &value, sizeof(value));

        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, boost::array<unsigned char, 16>>::const_iterator it = m_ip6s.begin();
         it != m_ip6s.end(); ++it)
    {
        std::string command;
        boost::uint32_t type = variable_type::k_ip6 | it->first;

        command.resize(sizeof(type) + it->second.max_size());
        memcpy(&command[0], &type, sizeof(type));
        memcpy(&command[4], &it->second[0], it->second.max_size());

        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, std::string>::const_iterator it = m_strings.begin();
         it != m_strings.end(); ++it)
    {
        std::string command;
        boost::uint32_t type = variable_type::k_string | it->first;

        if (it->second.size() > 255)
        {
            // two byte length
            boost::uint16_t length = it->second.size();
            command.resize(sizeof(type) + sizeof(length));

            memcpy(&command[0], &type, sizeof(type));
            memcpy(&command[4], &length, sizeof(length));
            command.append(it->second.data(), it->second.size());
        }
        else
        {
            // one byte length
            type |= variable_type::k_short_length;
            boost::uint8_t length = it->second.size();
            command.resize(sizeof(type) + sizeof(length));

            memcpy(&command[0], &type, sizeof(type));
            command[4] = length;
            command.append(it->second.data(), it->second.size());
        }

        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, WinboxMessage>::const_iterator it = m_msgs.begin();
        it != m_msgs.end(); ++it)
    {
        std::string command;
        boost::uint32_t type = variable_type::k_message | it->first;

        std::string serialized("M2");
        serialized.append(it->second.serialize_to_binary());

        if (serialized.size() > 255)
        {
            // two byte length
            boost::uint16_t length = serialized.size();
            command.resize(sizeof(type) + sizeof(length));

            memcpy(&command[0], &type, sizeof(type));
            memcpy(&command[4], &length, sizeof(length));
            command.append(serialized.data(), serialized.size());
        }
        else
        {
            // one byte length
            type |= variable_type::k_short_length;
            boost::uint8_t length = serialized.size();
            command.resize(sizeof(type) + sizeof(length));

            memcpy(&command[0], &type, sizeof(type));
            command[4] = length;
            command.append(serialized.data(), serialized.size());
        }

        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, std::string>::const_iterator it = m_raw.begin();
         it != m_raw.end(); ++it)
    {
        std::string command;
        boost::uint32_t type = variable_type::k_raw | it->first;

        if (it->second.length() > 255)
        {
            // two byte length
            boost::uint16_t length = it->second.length();
            command.resize(sizeof(type) + sizeof(length));

            memcpy(&command[0], &type, sizeof(type));
            memcpy(&command[4], &length, sizeof(length));
            command.append(it->second.data(), it->second.length());
        }
        else
        {
            // one byte length
            type |= variable_type::k_short_length;
            boost::uint8_t length = it->second.length();
            command.resize(sizeof(type) + sizeof(length));

            memcpy(&command[0], &type, sizeof(type));
            command[4] = length;
            command.append(it->second.data(), it->second.length());
        }

        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, std::vector<bool> >::const_iterator it = m_bool_array.begin();
         it != m_bool_array.end(); ++it)
    {
        boost::uint32_t type = variable_type::k_bool_array | it->first;
        boost::uint16_t array_size = it->second.size();

        std::string command;
        command.resize(sizeof(type) + sizeof(array_size) + (array_size * sizeof(char)));
        memcpy(&command[0], &type, sizeof(type));
        memcpy(&command[4], &array_size, sizeof(array_size));
        for (boost::uint16_t i = 0; i < array_size; i++)
        {
            command[i + 6] = it->second[i];
        }

        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, std::vector<boost::uint32_t> >::const_iterator it = m_u32_array.begin();
         it != m_u32_array.end(); ++it)
    {
        boost::uint32_t type = variable_type::k_u32_array | it->first;
        boost::uint16_t array_size = it->second.size();

        std::string command;
        command.resize(sizeof(type) + sizeof(array_size) + (array_size * sizeof(boost::uint32_t)));
        memcpy(&command[0], &type, sizeof(type));
        memcpy(&command[4], &array_size, sizeof(array_size));
        for (boost::uint16_t i = 0, j = 6; i < array_size; i++, j += sizeof(boost::uint32_t))
        {
            memcpy(&command[j], &it->second[i], sizeof(boost::uint32_t));
        }

        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, std::vector<boost::uint64_t> >::const_iterator it = m_u64_array.begin();
         it != m_u64_array.end(); ++it)
    {
        boost::uint32_t type = variable_type::k_u64_array | it->first;
        boost::uint16_t array_size = it->second.size();

        std::string command;
        command.resize(sizeof(type) + sizeof(array_size) + (array_size * sizeof(boost::uint64_t)));
        memcpy(&command[0], &type, sizeof(type));
        memcpy(&command[4], &array_size, sizeof(array_size));
        for (boost::uint16_t i = 0, j = 6; i < array_size; i++, j += sizeof(boost::uint64_t))
        {
            memcpy(&command[j], &it->second[i], sizeof(boost::uint64_t));
        }

        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, std::vector<boost::array<unsigned char, 16> > >::const_iterator it = m_ip6_array.begin();
        it != m_ip6_array.end(); ++it)
    {
        boost::uint32_t type = variable_type::k_ip6_array | it->first;
        boost::uint16_t array_size = it->second.size();

        std::string command;
        command.resize(sizeof(type) + sizeof(array_size) + (array_size * 16));
        memcpy(&command[0], &type, sizeof(type));
        memcpy(&command[4], &array_size, sizeof(array_size));
        for (boost::uint16_t i = 0, j = 6; i < array_size; i++, j += 16)
        {
            memcpy(&command[j], &it->second[i], 16);
        }

        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, std::vector<std::string> >::const_iterator it = m_string_array.begin();
        it != m_string_array.end(); ++it)
    {
        boost::uint32_t type = variable_type::k_string_array | it->first;
        boost::uint16_t array_size = it->second.size();

        std::string command;
        command.resize(sizeof(type) + sizeof(array_size));
        memcpy(&command[0], &type, sizeof(type));
        memcpy(&command[4], &array_size, sizeof(array_size));

        for (boost::uint16_t i = 0, j = 6; i < array_size; i++)
        {
            // insert the strings length
            boost::uint16_t length = it->second[i].size();
            command.resize(command.size() + sizeof(length));
            memcpy(&command[j], &length, sizeof(length));
            j += 2;

            // write the string
            command.resize(command.size() + length);
            memcpy(&command[j], it->second[i].data(), length);
            j += length;
        }

        return_val.append(command.data(), command.length());
    }

    for (std::map<boost::uint32_t, std::vector<WinboxMessage> >::const_iterator it = m_msg_array.begin();
         it != m_msg_array.end(); ++it)
    {
        boost::uint32_t type = variable_type::k_message_array | it->first;
        boost::uint16_t array_size = it->second.size();

        std::string command;
        command.resize(sizeof(type) + sizeof(array_size));
        memcpy(&command[0], &type, sizeof(type));
        memcpy(&command[4], &array_size, sizeof(array_size));

        for (boost::uint16_t i = 0, j = 6; i < array_size; i++)
        {
            // insert the message's length
            WinboxMessage temp_msg(it->second[i]);
            std::string temp_string(temp_msg.serialize_to_binary());

            boost::uint16_t length = temp_string.size();
            command.resize(command.size() + sizeof(length));
            memcpy(&command[j], &length, sizeof(length));
            j += 2;

            // write the string
            command.append(temp_string.data(), length);
            j += length;
        }

        return_val.append(command.data(), command.length());
    }


    for (std::map<boost::uint32_t, std::vector<std::string> >::const_iterator it = m_raw_array.begin();
         it != m_raw_array.end(); ++it)
    {
        boost::uint32_t type = variable_type::k_raw_array | it->first;
        boost::uint16_t array_size = it->second.size();

        std::string command;
        command.resize(sizeof(type) + sizeof(array_size));
        memcpy(&command[0], &type, sizeof(type));
        memcpy(&command[4], &array_size, sizeof(array_size));

        for (boost::uint16_t i = 0, j = 6; i < array_size; i++)
        {
            // insert the strings length
            boost::uint16_t length = it->second[i].size();
            command.resize(command.size() + sizeof(length));
            memcpy(&command[j], &length, sizeof(length));
            j += 2;

            // write the string
            command.resize(command.size() + length);
            memcpy(&command[j], it->second[i].data(), length);
            j += length;
        }

        return_val.append(command.data(), command.length());
    }

    return return_val;
}

//TODO I don't get raw or ip6
std::string WinboxMessage::serialize_to_json() const
{
    std::stringstream return_val;
    return_val << "{";

    bool first = true;
    for (std::map<boost::uint32_t, bool>::const_iterator it = m_bools.begin(); it != m_bools.end(); ++it)
    {
        do_comma(return_val, first);
        return_val << "b";
        return_val << std::hex << it->first;
        return_val << ":" << it->second;
    }

    for (std::map<boost::uint32_t, boost::uint32_t>::const_iterator it = m_u32s.begin(); it != m_u32s.end(); ++it)
    {
        do_comma(return_val, first);
        return_val << "u";
        return_val << std::hex << it->first;
        return_val << ":";
        return_val << std::dec << it->second;
    }

    for (std::map<boost::uint32_t, boost::uint64_t>::const_iterator it = m_u64s.begin(); it != m_u64s.end(); ++it)
    {
        do_comma(return_val, first);
        return_val << "q";
        return_val << std::hex << it->first;
        return_val << ":";
        return_val << std::dec << it->second;
    }

    for (std::map<boost::uint32_t, std::string>::const_iterator it = m_strings.begin(); it != m_strings.end(); ++it)
    {
        do_comma(return_val, first);
        return_val << "s";
        return_val << std::hex << it->first;
        return_val << ":'" << it->second << "'";
    }

    for (std::map<boost::uint32_t, std::string>::const_iterator it = m_raw.begin(); it != m_raw.end(); ++it)
    {
        do_comma(return_val, first);
        return_val << "r";
        return_val << std::hex << it->first;
        return_val << ":[";

        bool array_first = true;
        for (std::size_t i = 0; i < it->second.size(); i++)
        {
            do_comma(return_val, array_first);
            return_val << std::dec << (static_cast<int>(it->second[i]) & 0xff);
        }

        return_val << "]";
    }

    for (std::map<boost::uint32_t, WinboxMessage>::const_iterator it = m_msgs.begin(); it != m_msgs.end(); ++it)
    {
        do_comma(return_val, first);
        return_val << "m";
        return_val << std::hex << it->first;
        return_val << ":" << it->second.serialize_to_json();
    }

    for (std::map<boost::uint32_t, std::vector<bool> >::const_iterator it = m_bool_array.begin(); it != m_bool_array.end(); ++it)
    {
        do_comma(return_val, first);
        return_val << "B";
        return_val << std::hex << it->first;
        return_val << ":[";

        bool array_first = true;
        for (std::size_t i = 0; i < it->second.size(); i++)
        {
            do_comma(return_val, array_first);
            return_val << std::dec << it->second[i];
        }

        return_val << "]";
    }

    for (std::map<boost::uint32_t, std::vector<boost::uint32_t> >::const_iterator it = m_u32_array.begin(); it != m_u32_array.end(); ++it)
    {
        do_comma(return_val, first);
        return_val << "U";
        return_val << std::hex << it->first;
        return_val << ":[";

        bool array_first = true;
        for (std::size_t i = 0; i < it->second.size(); i++)
        {
            do_comma(return_val, array_first);
            return_val << std::dec << it->second[i];
        }

        return_val << "]";
    }

    for (std::map<boost::uint32_t, std::vector<boost::uint64_t> >::const_iterator it = m_u64_array.begin(); it != m_u64_array.end(); ++it)
    {
        do_comma(return_val, first);
        return_val << "Q";
        return_val << std::hex << it->first;
        return_val << ":[";

        bool array_first = true;
        for (std::size_t i = 0; i < it->second.size(); i++)
        {
            do_comma(return_val, array_first);
            return_val << std::dec << it->second[i];
        }

        return_val << "]";
    }

    for (std::map<boost::uint32_t, std::vector<std::string> >::const_iterator it = m_string_array.begin(); it != m_string_array.end(); ++it)
    {
        do_comma(return_val, first);
        return_val << "S";
        return_val << std::hex << it->first;
        return_val << ":[";

        bool array_first = true;
        for (std::size_t i = 0; i < it->second.size(); i++)
        {
            do_comma(return_val, array_first);
            return_val << "'" << it->second[i] << "'";
        }

        return_val << "]";
    }

    for (std::map<boost::uint32_t, std::vector<WinboxMessage> >::const_iterator it = m_msg_array.begin(); it != m_msg_array.end(); ++it)
    {
        do_comma(return_val, first);
        return_val << "M";
        return_val << std::hex << it->first;
        return_val << ":[";

        bool array_first = true;
        for (std::size_t i = 0; i < it->second.size(); i++)
        {
            do_comma(return_val, array_first);
            return_val << it->second[i].serialize_to_json();
        }

        return_val << "]";
    }


    return_val << "}";
    return return_val.str();
}

bool WinboxMessage::parse_binary(const std::string& p_input)
{
    std::string input(p_input);

    // if this starts out with M2 then the caller didn't trim the lead
    // in M2 header. That's fine, just erase it.
    if (input.size() > 2 && memcmp(input.data(), "M2", 2) == 0)
    {
        input.erase(0, 2);
    }

    while (input.length() >= 4)
    {
        boost::uint32_t type_name = *reinterpret_cast<const boost::uint32_t*>(&input[0]);
        boost::uint32_t type = type_name & 0xf8000000;
        boost::uint32_t name = type_name & 0x00ffffff;
        input.erase(0, 4);

        switch (type)
        {
            case variable_type::k_bool:
                {
                    m_bools.insert(std::make_pair(name, (type_name & variable_type::k_short_length) != 0));
                }
                break;
            case variable_type::k_u32:
                {
                    if (type_name & variable_type::k_short_length && input.size())
                    {
                        m_u32s.insert(std::make_pair(name, input[0] & 0xff));
                        input.erase(0, 1);
                    }
                    else if (input.size() >= 4)
                    {
                        boost::uint32_t value = *reinterpret_cast<const boost::uint32_t*>(&input[0]);
                        m_u32s.insert(std::make_pair(name, value));
                        input.erase(0, 4);
                    }
                }
                break;
            case variable_type::k_u64:
                {
                    if (input.size() >= 8)
                    {
                        boost::uint64_t value = *reinterpret_cast<const boost::uint64_t*>(&input[0]);
                        m_u64s.insert(std::make_pair(name, value));
                        input.erase(0, 8);
                    }
                }
                break;
            case variable_type::k_ip6:
                {
                    if (input.size() >= 16)
                    {
                        boost::array<unsigned char, 16> value = { { } };
                        memcpy(&value[0], &input[0], 16);
                        m_ip6s.insert(std::make_pair(name, value));
                        input.erase(0, 16);
                    }
                }
                break;
            case variable_type::k_raw: 
            case variable_type::k_string:
                {
                    if (input.size() >= 2)
                    {
                        boost::uint16_t length = input[0] & 0xff;
                        if (type_name & variable_type::k_short_length)
                        {
                            input.erase(0, 1);
                        }
                        else
                        {
                            length = *reinterpret_cast<const boost::uint16_t*>(&input[0]);
                            input.erase(0, 2);
                        }

                        if (input.size() >= length)
                        {
                            std::string value(input.data(), length);
                            if (type == variable_type::k_raw)
                            {
                                m_raw.insert(std::make_pair(name, value));
                            }
                            else
                            {
                                m_strings.insert(std::make_pair(name, value));
                            }
                            input.erase(0, length);
                        }
                        else
                        {
                            // its hard to account for the weird seperators that
                            // MT has inserted mid message. Just mark the entire
                            // remaining message as raw and get on with life
                            if (type == variable_type::k_raw)
                            {
                                m_raw.insert(std::make_pair(name, input));
                            }
                            else
                            {
                                m_strings.insert(std::make_pair(name, input));
                            }
                            input.clear();
                        }
                    }
                }
                break;
            case variable_type::k_message:
                {
                    if (input.size() >= 2)
                    {
                        boost::uint16_t length = input[0] & 0xff;
                        if (type_name & variable_type::k_short_length)
                        {
                            input.erase(0, 1);
                        }
                        else
                        {
                            length = *reinterpret_cast<const boost::uint16_t*>(&input[0]);
                            input.erase(0, 2);
                        }

                        if (input.size() >= length)
                        {
                            // note that this recursion is the exact issue I reported
                            // to Mikrotik.
                            std::string value(input.data(), length);
                            if (value.size() > 2 && value[0] == 'M' && value[1] == '2')
                            {
                                value.erase(0, 2);
                                WinboxMessage temp;
                                temp.parse_binary(value);
                                m_msgs.insert(std::make_pair(name, temp));
                                input.erase(0, length);
                            }
                        }
                        else if (input.size() > 2 && input[0] == 'M' && input[1] == '2')
                        {
                            // its hard to account for the weird seperators that
                            // MT has inserted mid message. Just mark the entire
                            // remaining message as msg and get on with life
                            input.erase(0, 2);
                            WinboxMessage temp;
                            temp.parse_binary(input);
                            m_msgs.insert(std::make_pair(name, temp));
                            input.clear();
                        }
                    }
                }
                break;
            case variable_type::k_bool_array:
                {
                    if (input.size() >= 2)
                    {
                        boost::uint16_t entries = *reinterpret_cast<const boost::uint16_t*>(&input[0]);
                        input.erase(0, 2);

                        std::vector<bool> bools;
                        if (input.size() >= entries)
                        {
                            for (std::size_t i = 0; i < entries; i++)
                            {
                                bools.push_back(input[i] == 1);
                            }
                            input.erase(0, entries);
                        }
                        m_bool_array.insert(std::make_pair(name, bools));
                    }
                }
                break;
            case variable_type::k_u32_array:
                {
                    if (input.size() >= 2)
                    {
                        boost::uint16_t entries = *reinterpret_cast<const boost::uint16_t*>(&input[0]);
                        input.erase(0, 2);

                        std::vector<boost::uint32_t> u32s;
                        if (input.size() >= (entries * sizeof(boost::uint32_t)))
                        {
                            for (std::size_t i = 0; i < entries; i++)
                            {
                                u32s.push_back(*reinterpret_cast<boost::uint32_t*>(&input[i * sizeof(boost::uint32_t)]));
                            }
                            input.erase(0, entries * sizeof(boost::uint32_t));
                        }
                        m_u32_array.insert(std::make_pair(name, u32s));
                    }
                }
                break;
            case variable_type::k_u64_array:
                {
                    if (input.size() >= 2)
                    {
                        boost::uint16_t entries = *reinterpret_cast<const boost::uint16_t*>(&input[0]);
                        input.erase(0, 2);

                        std::vector<boost::uint64_t> u64s;
                        if (input.size() >= (entries * sizeof(boost::uint64_t)))
                        {
                            for (std::size_t i = 0; i < entries; i++)
                            {
                                u64s.push_back(*reinterpret_cast<boost::uint64_t*>(&input[i * sizeof(boost::uint64_t)]));
                            }
                            input.erase(0, entries * sizeof(boost::uint64_t));
                        }
                        m_u64_array.insert(std::make_pair(name, u64s));
                    }
                }
                break;
            case variable_type::k_ip6_array:
                {
                    if (input.size() >= 2)
                    {
                        boost::uint16_t entries = *reinterpret_cast<const boost::uint16_t*>(&input[0]);
                        input.erase(0, 2);

                        std::vector<boost::array<unsigned char, 16> > ip6s;
                        if (input.size() >= (entries * 16))
                        {
                            for (std::size_t i = 0; i < entries; i++)
                            {
                                boost::array<unsigned char, 16> ip = { { } };
                                memcpy(&ip[0], &input[i * 16], 16);
                                ip6s.push_back(ip);
                            }
                            input.erase(0, entries * 16);
                        }
                        m_ip6_array.insert(std::make_pair(name, ip6s));
                    }
                }
                break;
            case variable_type::k_raw_array:
            case variable_type::k_string_array:
                {
                    if (input.size() >= 2)
                    {
                        boost::uint16_t entries = *reinterpret_cast<const boost::uint16_t*>(&input[0]);
                        input.erase(0, 2);

                        std::vector<std::string> strings;
                        if (input.size() >= (entries * 3))
                        {
                            std::size_t consumed = 0;
                            for (std::size_t i = 0; i < entries && consumed < input.size(); i++)
                            {
                                if ((consumed + 2) < input.size())
                                {
                                    std::size_t length = *reinterpret_cast<const boost::uint16_t*>(&input[consumed]);
                                    consumed += 2;

                                    if ((consumed + length) <= input.size())
                                    {
                                        std::string temp_string(&input[consumed], length);
                                        strings.push_back(temp_string);
                                        consumed += length;
                                    }
                                }
                            }
                            input.erase(0, consumed);
                        }
                        if (type == variable_type::k_raw_array)
                        {
                            m_raw_array.insert(std::make_pair(name, strings));
                        }
                        else
                        {
                            m_string_array.insert(std::make_pair(name, strings));
                        }
                    }
                }
                break;
            case variable_type::k_message_array:
                {
                    if (input.size() >= 2)
                    {
                        boost::uint16_t entries = *reinterpret_cast<const boost::uint16_t*>(&input[0]);
                        input.erase(0, 2);

                        std::vector<WinboxMessage> msgs;
                        if (input.size() >= (entries * 6))
                        {
                            std::size_t consumed = 0;
                            for (std::size_t i = 0; i < entries && consumed < input.size(); i++)
                            {
                                if ((consumed + 2) < input.size())
                                {
                                    std::size_t length = *reinterpret_cast<const boost::uint16_t*>(&input[consumed]);
                                    consumed += 2;

                                    if ((consumed + length) <= input.size())
                                    {
                                        std::string temp_string(&input[consumed], length);
                                        if (temp_string.size() > 2 && temp_string[0] == 'M' && temp_string[1] == '2')
                                        {
                                            temp_string.erase(0, 2);
                                            WinboxMessage temp_message;
                                            temp_message.parse_binary(temp_string);

                                            msgs.push_back(temp_message);
                                            consumed += length;
                                        }
                                    }
                                }
                            }
                            input.erase(0, consumed);
                        }
                        m_msg_array.insert(std::make_pair(name, msgs));
                    }
                }
                break;
            default:
                //std::cerr << "Parsing error: " << std::hex << ((int)type & 0xff) << std::endl;
                break;
        }
    }
    return true;
}

bool WinboxMessage::parse_json(const std::string& p_input)
{
    if (p_input.size() <= 1 || p_input[0] != '{')
    {
        return false;
    }

    std::string input(p_input.data() + 1, p_input.size() - 1);

    while (input.size() >= 4)
    {
        char type = input[0];
        input.erase(0, 1);

        std::size_t variable_end = input.find(':');
        if (variable_end == std::string::npos)
        {
            return false;
        }

        // extract the variable name
        std::string variable_string(input.data(), variable_end);
        input.erase(0, variable_end + 1);

        // convert the variable into an int
        boost::uint32_t variable = 0;
        try
        {
            variable = std::stoi(variable_string, 0, 16);
        }
        catch (const std::exception&)
        {
            return false;
        }

        switch (type)
        {
            case 'b':
                {
                    if (input.size() > 1)
                    {
                        if (input[0] == '1')
                        {
                            m_bools.insert(std::make_pair(variable, true));
                        }
                        else if (input[0] == '0')
                        {
                            m_bools.insert(std::make_pair(variable, false));
                        }
                        else
                        {
                            return false;
                        }
                        input.erase(0, 1);
                    }
                }
                break;
            case 'u':
                {
                    std::regex capture_int("^([0-9]+)");
                    std::smatch match;
                    if (!std::regex_search(input, match, capture_int))
                    {
                        return false;
                    }
                    std::string value_string(match[0]);
                    input.erase(0, value_string.size());

                    try
                    {
                        boost::uint32_t value = std::stoi(value_string);
                        m_u32s.insert(std::make_pair(variable, value));
                    }
                    catch (const std::exception&)
                    {
                        return false;
                    }
                }
                break;
            case 'q':
                {
                    std::regex capture_int("^([0-9]+)");
                    std::smatch match;
                    if (!std::regex_search(input, match, capture_int))
                    {
                        return false;
                    }
                    std::string value_string(match[0]);
                    input.erase(0, value_string.size());

                    try
                    {
                        boost::uint64_t value = std::stoll(value_string);
                        m_u64s.insert(std::make_pair(variable, value));
                    }
                    catch (const std::exception&)
                    {
                        return false;
                    }
                }
                break;
            case 'r':
                {
                    std::regex capture_string("^\\[([,0-9]+)\\]");
                    std::smatch match;
                    if (!std::regex_search(input, match, capture_string))
                    {
                        return false;
                    }
                    std::string full_match(match[0]);
                    std::string value_string(match[1]);
                    input.erase(0, full_match.size());

                    std::vector<std::string> raw_chars;
                    boost::split(raw_chars, value_string, boost::is_any_of(","));

                    std::string result;
                    for (std::size_t i = 0; i < raw_chars.size(); i++)
                    {
                        result.push_back((char)strtoul(raw_chars[i].c_str(), NULL, 10));
                    }

                    m_raw.insert(std::make_pair(variable, result));
                }
                break;
            case 's':
                {
                    //TODO this is so far from perfect but good enough
                    std::regex capture_string("^'(.+?)'(?:,|})");
                    std::smatch match;
                    if (!std::regex_search(input, match, capture_string))
                    {
                        return false;
                    }
                    std::string full_match(match[0]);
                    std::string value_string(match[1]);
                    input.erase(0, full_match.size() - 1);
                    m_strings.insert(std::make_pair(variable, value_string));
                }
                break;
            case 'm':
                {
                    //TODO this is so far from perfect but good enough
                    std::regex capture_message("^(\\{.+?\\})(?:,|})");
                    std::smatch match;
                    if (!std::regex_search(input, match, capture_message))
                    {
                        return false;
                    }
                    std::string full_match(match[0]);
                    std::string value_string(match[1]);
                    input.erase(0, full_match.size() - 1);

                    WinboxMessage temp_msg;
                    if (!temp_msg.parse_json(value_string))
                    {
                        return false;
                    }
                    m_msgs.insert(std::make_pair(variable, temp_msg));
                }
                break;
            case 'B':
                {
                    //TODO this is so far from perfect but good enough
                    std::regex capture_message("^\\[([0-1,]+)\\](?:,|})");
                    std::smatch match;
                    if (!std::regex_search(input, match, capture_message))
                    {
                        return false;
                    }
                    std::string full_match(match[0]);
                    std::string value_string(match[1]);
                    input.erase(0, full_match.size() - 1);

                    std::vector<std::string> bools_strings;
                    boost::split(bools_strings, value_string, boost::is_any_of(","));

                    std::vector<bool> bools;
                    for (std::size_t i = 0; i < bools_strings.size(); i++)
                    {
                        bools.push_back(bools_strings[i] == "1");
                    }
                    m_bool_array.insert(std::make_pair(variable, bools));
                }
                break;
            case 'U':
                {
                    //TODO this is so far from perfect but good enough
                    std::regex capture_message("^\\[([0-9,]+)\\](?:,|})");
                    std::smatch match;
                    if (!std::regex_search(input, match, capture_message))
                    {
                        return false;
                    }
                    std::string full_match(match[0]);
                    std::string value_string(match[1]);
                    input.erase(0, full_match.size() - 1);

                    std::vector<std::string> u32_strings;
                    boost::split(u32_strings, value_string, boost::is_any_of(","));

                    std::vector<boost::uint32_t> u32s;
                    for (std::size_t i = 0; i < u32_strings.size(); i++)
                    {
                        try
                        {
                            u32s.push_back(std::stoi(u32_strings[i]));
                        }
                        catch (const std::exception&)
                        {
                            return false;
                        }
                    }
                    m_u32_array.insert(std::make_pair(variable, u32s));
                }
                break;
            case 'Q':
                {
                    //TODO this is so far from perfect but good enough
                    std::regex capture_message("^\\[([0-9,]+)\\](?:,|})");
                    std::smatch match;
                    if (!std::regex_search(input, match, capture_message))
                    {
                        return false;
                    }
                    std::string full_match(match[0]);
                    std::string value_string(match[1]);
                    input.erase(0, full_match.size() - 1);

                    std::vector<std::string> u64_strings;
                    boost::split(u64_strings, value_string, boost::is_any_of(","));

                    std::vector<boost::uint64_t> u64s;
                    for (std::size_t i = 0; i < u64_strings.size(); i++)
                    {
                        try
                        {
                            u64s.push_back(std::stoll(u64_strings[i]));
                        }
                        catch (const std::exception&)
                        {
                            return false;
                        }
                    }
                    m_u64_array.insert(std::make_pair(variable, u64s));
                }
                break;
            case 'S':
                {
                    //TODO this is so far from perfect but good enough
                    std::regex capture_message("^\\[(.+?)\\](?:,|})");
                    std::smatch match;
                    if (!std::regex_search(input, match, capture_message))
                    {
                        return false;
                    }

                    std::string full_match(match[0]);
                    std::string value_string(match[1]);
                    input.erase(0, full_match.size() - 1);

                    std::vector<std::string> strings;
                    boost::split(strings, value_string, boost::is_any_of(","));

                    // trim the single quotes around the strings
                    for (std::size_t i = 0; i < strings.size(); i++)
                    {
                        if (strings[i][0] != '\'' || strings[i][strings[i].size() - 1] != '\'')
                        {
                            return false;
                        }
                        strings[i].erase(0, 1);
                        strings[i].resize(strings[i].size() - 1);
                    }
                    m_string_array.insert(std::make_pair(variable, strings));
                }
                break;
            case 'M':
                {
                    //TODO this is so far from perfect but good enough
                    std::regex capture_message("^\\[(.+?)\\](?:,|})");
                    std::smatch match;
                    if (!std::regex_search(input, match, capture_message))
                    {
                        return false;
                    }

                    std::string full_match(match[0]);
                    std::string value_string(match[1]);
                    input.erase(0, full_match.size() - 1);

                    std::vector<std::string> msg_strings;
                    boost::split(msg_strings, value_string, boost::is_any_of(","));

                    std::vector<WinboxMessage> msgs;
                    for (std::size_t i = 0; i < msg_strings.size(); i++)
                    {
                        WinboxMessage tmp_msg;
                        if (!tmp_msg.parse_json(msg_strings[i]))
                        {
                            return false;
                        }
                        msgs.push_back(tmp_msg);
                    }
                    m_msg_array.insert(std::make_pair(variable, msgs));
                }
                break;
            default:
                return false;
        }

        // find the end of this variable
        if (input.empty() || (input[0] != ',' && input[0] != '}'))
        {
            return false;
        }
        input.erase(0,1);
    }
    return true;
}

bool WinboxMessage::has_error() const
{
    return m_strings.find(variable_names::k_error_string) != m_strings.end() ||
           m_u32s.find(variable_names::k_error_code) != m_u32s.end();
}

std::string WinboxMessage::get_error_string() const
{
    if (has_error())
    {
        if (m_strings.find(variable_names::k_error_string) != m_strings.end())
        {
            return m_strings.find(variable_names::k_error_string)->second;
        }
        else if (m_u32s.find(variable_names::k_error_code) != m_u32s.end())
        {
            switch (m_u32s.find(variable_names::k_error_code)->second)
            {
                case error_codes::k_not_implemented:
                case error_codes::k_not_implementedv2:
                    return "Feature not implemented";
                case error_codes::k_obj_nonexistant:
                case error_codes::k_obj_nonexistant2:
                    return "Object doesn't exist";
                case error_codes::k_not_permitted:
                    return "Not permitted";
                case error_codes::k_timeout:
                    return "Timeout";
                case error_codes::k_busy:
                    return "Busy";
                default:
                    return "Unknown error code";
            }
        }
    }
    return std::string();
}

boost::uint32_t WinboxMessage::get_session_id() const
{
    return get_u32(variable_names::k_session_id);
}

bool WinboxMessage::get_boolean(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, bool>::const_iterator it = m_bools.find(p_name);
    if (it != m_bools.end())
    {
        return it->second;
    }
    return 0;
}

boost::uint32_t WinboxMessage::get_u32(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, boost::uint32_t>::const_iterator it = m_u32s.find(p_name);
    if (it != m_u32s.end())
    {
        return it->second;
    }
    return 0;
}

boost::uint64_t WinboxMessage::get_u64(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, boost::uint64_t>::const_iterator it = m_u64s.find(p_name);
    if (it != m_u64s.end())
    {
        return it->second;
    }
    return 0;
}

boost::array<unsigned char, 16> WinboxMessage::get_ip6(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, boost::array<unsigned char, 16> >::const_iterator it = m_ip6s.find(p_name);
    if (it != m_ip6s.end())
    {
        return it->second;
    }
    return { { } };
}

std::string WinboxMessage::get_raw(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, std::string>::const_iterator it = m_raw.find(p_name);
    if (it != m_raw.end())
    {
        return it->second;
    }
    return std::string();
}

std::string WinboxMessage::get_string(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, std::string>::const_iterator it = m_strings.find(p_name);
    if (it != m_strings.end())
    {
        return it->second;
    }
    return std::string();
}

WinboxMessage WinboxMessage::get_msg(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, WinboxMessage>::const_iterator it = m_msgs.find(p_name);
    if (it != m_msgs.end())
    {
        return it->second;
    }
    return WinboxMessage();
}

std::vector<bool> WinboxMessage::get_boolean_array(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, std::vector<bool> >::const_iterator it = m_bool_array.find(p_name);
    if (it != m_bool_array.end())
    {
        return it->second;
    }
    return std::vector<bool>();
}

std::vector<boost::uint32_t> WinboxMessage::get_u32_array(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, std::vector<boost::uint32_t> >::const_iterator it = m_u32_array.find(p_name);
    if (it != m_u32_array.end())
    {
        return it->second;
    }
    return std::vector<boost::uint32_t>();
}

std::vector<boost::uint64_t> WinboxMessage::get_u64_array(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, std::vector<boost::uint64_t> >::const_iterator it = m_u64_array.find(p_name);
    if (it != m_u64_array.end())
    {
        return it->second;
    }
    return std::vector<boost::uint64_t>();
}

std::vector<boost::array<unsigned char, 16> > WinboxMessage::get_ip6_array(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, std::vector<boost::array<unsigned char, 16> > >::const_iterator it = m_ip6_array.find(p_name);
    if (it != m_ip6_array.end())
    {
        return it->second;
    }
    return std::vector<boost::array<unsigned char, 16> >();
}

std::vector<std::string> WinboxMessage::get_string_array(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, std::vector<std::string> >::const_iterator it = m_string_array.find(p_name);
    if (it != m_string_array.end())
    {
        return it->second;
    }
    return std::vector<std::string>();
}

std::vector<WinboxMessage> WinboxMessage::get_msg_array(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, std::vector<WinboxMessage> >::const_iterator it = m_msg_array.find(p_name);
    if (it != m_msg_array.end())
    {
        return it->second;
    }
    return std::vector<WinboxMessage>();
}

std::vector<std::string> WinboxMessage::get_raw_array(boost::uint32_t p_name) const
{
    std::map<boost::uint32_t, std::vector<std::string> >::const_iterator it = m_raw_array.find(p_name);
    if (it != m_raw_array.end())
    {
        return it->second;
    }
    return std::vector<std::string>();
}

void WinboxMessage::set_to(boost::uint32_t p_to)
{
    m_u32_array.erase(variable_names::k_sys_to);

    std::vector<boost::uint32_t> to;
    to.push_back(p_to);
    add_u32_array(variable_names::k_sys_to, to);
}

void WinboxMessage::set_to(boost::uint32_t p_to, boost::uint32_t p_handler)
{
    m_u32_array.erase(variable_names::k_sys_to);

    std::vector<boost::uint32_t> to;
    to.push_back(p_to);
    to.push_back(p_handler);
    add_u32_array(variable_names::k_sys_to, to);
}

void WinboxMessage::set_command(boost::uint32_t p_command)
{
    add_u32(variable_names::k_command, p_command);
}

void WinboxMessage::set_reply_expected(bool p_reply_expected)
{
    add_boolean(variable_names::k_reply_expected, p_reply_expected);
}

void WinboxMessage::set_request_id(boost::uint32_t p_id)
{
    add_u32(variable_names::k_request_id, p_id);
}

void WinboxMessage::set_session_id(boost::uint32_t p_session_id)
{
    add_u32(variable_names::k_session_id, p_session_id);
}

void WinboxMessage::add_boolean(boost::uint32_t p_name, bool p_value)
{
    m_bools[p_name] = p_value;
}

void WinboxMessage::add_u32(boost::uint32_t p_name, boost::uint32_t p_value)
{
    m_u32s[p_name] = p_value;
}

void WinboxMessage::add_u64(boost::uint32_t p_name, boost::uint64_t p_value)
{
    m_u64s.insert(std::make_pair(p_name, p_value));
}

void WinboxMessage::add_ip6(boost::uint32_t p_name, boost::array<unsigned char, 16> p_value)
{
    m_ip6s.insert(std::make_pair(p_name, p_value));
}

void WinboxMessage::add_string(boost::uint32_t p_name, const std::string& p_string)
{
    m_strings.insert(std::make_pair(p_name, p_string));
}

void WinboxMessage::add_msg(boost::uint32_t p_name, const WinboxMessage& p_msg)
{
    m_msgs.insert(std::make_pair(p_name, p_msg));
}

void WinboxMessage::add_raw(boost::uint32_t p_name, const std::string& p_raw)
{
    m_raw.insert(std::make_pair(p_name, p_raw));
}

void WinboxMessage::add_boolean_array(boost::uint32_t p_name, const std::vector<bool>& p_value)
{
    m_bool_array.insert(std::make_pair(p_name, p_value));
}

void WinboxMessage::add_u32_array(boost::uint32_t p_name, const std::vector<boost::uint32_t>& p_value)
{
    m_u32_array.insert(std::make_pair(p_name, p_value));
}

void WinboxMessage::add_u64_array(boost::uint32_t p_name, const std::vector<boost::uint64_t>& p_value)
{
    m_u64_array.insert(std::make_pair(p_name, p_value));
}

void WinboxMessage::add_ip6_array(boost::uint32_t p_name, const std::vector<boost::array<unsigned char, 16> >& p_value)
{
    m_ip6_array.insert(std::make_pair(p_name, p_value));
}

void WinboxMessage::add_string_array(boost::uint32_t p_name, const std::vector<std::string>& p_value)
{
    m_string_array.insert(std::make_pair(p_name, p_value));
}

void WinboxMessage::add_msg_array(boost::uint32_t p_name, const std::vector<WinboxMessage>& p_value)
{
    m_msg_array.insert(std::make_pair(p_name, p_value));
}

void WinboxMessage::add_raw_array(boost::uint32_t p_name, const std::vector<std::string>& p_value)
{
    m_raw_array.insert(std::make_pair(p_name, p_value));
}

void WinboxMessage::erase_u32(boost::uint32_t p_name)
{
    m_u32s.erase(p_name);
}
