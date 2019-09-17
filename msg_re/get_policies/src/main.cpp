#include <list>
#include <map>
#include <vector>
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <algorithm>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include "winbox_session.hpp"
#include "winbox_message.hpp"

namespace
{
    const char s_version[] = "lol";

    bool parseCommandLine(int p_argCount, const char* p_argArray[],
                          std::string& p_ip, std::string& p_port,
                          std::string& p_x3_csv, std::string& p_csv_file)
    {
        boost::program_options::options_description description("options");
        description.add_options()
            ("help,h", "A list of command line options")
            ("version,v", "Display version information")
            ("port,p", boost::program_options::value<std::string>(), "The port to connect to")
            ("ip,i", boost::program_options::value<std::string>(), "The ip to connect to")
            ("handler_csv,d", boost::program_options::value<std::string>(), "The csv containing the handler numbers")
            ("x3_csv,x", boost::program_options::value<std::string>(), "The csv containing the x3 numbers");

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

        if (argv_map.count("ip") && argv_map.count("port") &&
            argv_map.count("handler_csv") && argv_map.count("x3_csv"))
        {
            p_ip.assign(argv_map["ip"].as<std::string>());
            p_port.assign(argv_map["port"].as<std::string>());
            p_x3_csv.assign(argv_map["x3_csv"].as<std::string>());
            p_csv_file.assign(argv_map["handler_csv"].as<std::string>());
            return true;
        }
        else
        {
            std::cout << description << std::endl;
        }

        return false;
    }

    std::map<boost::uint32_t, std::string> parse_x3_file(const std::string& p_file)
    {
        std::map<boost::uint32_t, std::string> return_val;

        std::ifstream x3_file(p_file);
        if (x3_file.is_open())
        {
            std::string line;
            while (getline(x3_file, line))
            {

                if (line.empty())
                {
                    continue;
                }

                if (line[0] == ',')
                {
                    line.erase(0, 1);
                    boost::uint32_t id = std::stoul(line, 0, 10);
                    return_val.insert(std::make_pair(id, std::string()));
                }
                else
                {
                    std::vector<std::string> entry;
                    boost::split(entry, line, boost::is_any_of(","));
                    if (entry.size() != 2)
                    {
                        continue;
                    }
                    boost::uint32_t id = std::stoul(entry[1], 0, 10);
                    return_val.insert(std::make_pair(id, entry[0]));
                }
            }
        }
        x3_file.close();
        return return_val;
    }

    std::map<std::string, std::vector<boost::uint32_t> > parse_handler_file(const std::string& p_file)
    {
        std::map<std::string, std::vector<boost::uint32_t> > return_val;

        std::ifstream handler_file(p_file);
        if (handler_file.is_open())
        {
            std::string line;
            while (getline(handler_file, line))
            {
                if (line.empty())
                {
                    continue;
                }

                std::vector<std::string> entry;
                boost::split(entry, line, boost::is_any_of(","));
                if (entry.size() < 2)
                {
                    continue;
                }
                for (std::size_t i = 1; i < entry.size(); i++)
                {
                    if (entry[i].empty())
                    {
                        continue;
                    }
                    if (entry[i].size() > 2 && entry[i][1] == 'x')
                    {
                        boost::uint32_t id = std::stoul(entry[i], 0, 16);
                        return_val[entry[0]].push_back(id);
                    }
                    else
                    {
                        boost::uint32_t id = std::stoul(entry[i], 0, 10);
                        return_val[entry[0]].push_back(id);
                    }
                }
            }
        }
        handler_file.close();
        return return_val;
    }

    std::map<std::string, std::map<boost::uint32_t, std::vector<boost::uint32_t> > > combine_maps(
        const std::map<boost::uint32_t, std::string>& p_x3,
        const std::map<std::string, std::vector<boost::uint32_t> >& p_handlers)
    {
        std::map<std::string, std::map<boost::uint32_t, std::vector<boost::uint32_t> > > ret_val;

        for (std::map<boost::uint32_t, std::string>::const_iterator x3 = p_x3.begin();
             x3 != p_x3.end(); ++x3)
        {
            bool found = false;

            // outter loop: look for the x3 -> handler relationship via binary name
            for (std::map<std::string, std::vector<boost::uint32_t> >::const_iterator handler = p_handlers.begin();
                 handler != p_handlers.end() && !found; ++handler)
            {
                if (boost::algorithm::ends_with(x3->second, handler->first))
                {
                    ret_val[x3->second].insert(std::make_pair(x3->first, handler->second));
                    std::sort(ret_val[x3->second][x3->first].begin(), ret_val[x3->second][x3->first].end());
                    found = true;
                }
            }

            if (!found)
            {
                // this case doesn'thave a handler
                ret_val[x3->second].insert(std::make_pair(x3->first, std::vector<boost::uint32_t>()));
            }
        }
        return ret_val;
    }

}

bool get_commands(Winbox_Session& p_session, boost::uint32_t& p_request_id, std::vector<boost::uint32_t> p_route)
{
    if (p_route[0] == 123 || p_route[0] == 133 || p_route[0] == 132 || p_route[0] == 134 || p_route[0] == 92 || p_route[0] == 94 || p_route[0] == 127 || p_route[0] == 109)
    {
        return false;
    }
    WinboxMessage msg;
    if (p_route.size() == 1)
    {
        msg.set_to(p_route[0]);
    }
    else
    {
        msg.set_to(p_route[0], p_route[1]);
    }
    msg.set_command(0xfe0004);
    msg.set_request_id(p_request_id);
    msg.set_reply_expected(true);
    p_session.send(msg);

    ++p_request_id;

    msg.reset();
    if (!p_session.receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return false;
    }

    if (msg.has_error())
    {
        std::cout << msg.get_error_string() << std::endl;
        return false;
    }

    std::cout << msg.serialize_to_json() << std::endl;
    /*std::map<boost::uint32_t, std::pair<boost::uint32_t, bool> > ordered;
    std::vector<WinboxMessage> policies(msg.get_msg_array(0xfe0002));
    for (std::vector<WinboxMessage>::const_iterator it = policies.begin();
         it != policies.end(); ++it)
    {
        ordered.insert(std::make_pair(it->get_u32(0xfe0001), std::make_pair(it->get_u32(1), it->get_boolean(2))));
    }

    for (std::map<boost::uint32_t, std::pair<boost::uint32_t, bool> >::const_iterator it = ordered.begin();
         it != ordered.end(); it++)
    {
        std::cout << "\t\t" << std::hex << it->first << " : " << it->second.first << " (" << it->second.second << ")" << std::endl;
    }*/

    return false;
}

int main(int p_argc, const char** p_argv)
{
    std::string ip;
    std::string port;
    std::string x3_file;
    std::string handler_file;
    if (!parseCommandLine(p_argc, p_argv, ip, port, x3_file, handler_file))
    {
        return EXIT_FAILURE;
    }

    std::map<boost::uint32_t, std::string> x3(parse_x3_file(x3_file));
    if (x3.empty())
    {
        std::cerr << "[-] Failed x3 parsing" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Found " << x3.size() << " x3 entries" << std::endl;

    std::map<std::string, std::vector<boost::uint32_t> > handlers(parse_handler_file(handler_file));
    if (handlers.empty())
    {
        std::cerr << "[-] Failed handler parsing" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Found " << handlers.size() << " handler entries" << std::endl;

    std::map<std::string, std::map<boost::uint32_t, std::vector<boost::uint32_t> > > routing_map(combine_maps(x3, handlers));
    if (routing_map.empty())
    {
        std::cerr << "[-] Failed combining the csv files" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] " << routing_map.size() << " top level entries in the routing map" << std::endl;

    for (std::map<std::string, std::map<boost::uint32_t, std::vector<boost::uint32_t> > >::const_iterator name = routing_map.begin();
         name != routing_map.end(); ++name)
    {
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

        boost::uint32_t request_id = 1;
        std::cout << "[+] " << name->first << std::endl;
        for (std::map<boost::uint32_t, std::vector<boost::uint32_t> >::const_iterator handler = name->second.begin();
             handler != name->second.end(); ++handler)
        {
            try
            {
                std::cout << "\t" << handler->first << std::endl;
                get_commands(winboxSession, request_id, { handler->first });

                for (std::size_t i = 0; i < handler->second.size(); i++)
                {
                    std::cout << "\t" << handler->first << ", " << handler->second[i] << std::endl;
                    get_commands(winboxSession, request_id, { handler->first, handler->second[i] });
                }
            }
            catch (...)
            {
            }
        }
    }

    return EXIT_SUCCESS;
}

