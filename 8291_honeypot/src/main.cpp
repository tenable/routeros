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
#include <cstdlib>
#include <iostream>
#include <GeoLite2PP.hpp>
#include <boost/asio.hpp>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>

#include "logging.hpp"
#include "mt_server.hpp"
#include "winbox_session.hpp"
#include "winbox_message.hpp"

namespace
{
    const char s_version[] = "MikroTik WinBox Honeypot Defcon Release";

    bool parseCommandLine(int p_argCount, const char* p_argArray[],
                          boost::uint16_t& p_port, std::string& p_log)
    {
        boost::program_options::options_description description("options");
        description.add_options()
        ("help,h", "A list of command line options")
        ("version,v", "Display version information")
        ("port,p", boost::program_options::value<boost::uint16_t>(), "The port to connect to listen on")
        ("log,l", boost::program_options::value<std::string>(), "The file to log to");

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
    
        if (argv_map.count("log"))
        {
            p_log.assign(argv_map["log"].as<std::string>());
        }

        if (argv_map.count("port"))
        {
            p_port = argv_map["port"].as<boost::uint16_t>();
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
    std::string logpath;
    boost::uint16_t listening_port = 0;
    if (parseCommandLine(p_argc, p_argv, listening_port, logpath) == false)
    {
        return EXIT_FAILURE;
    }

    Logging log(logpath);
    log.log(logging::k_info, "Loading GeoIP information from /var/lib/GeoIP/GeoLite2-City.mmdb");
    GeoLite2PP::DB geoDB("/var/lib/GeoIP/GeoLite2-City.mmdb");
    log.log(logging::k_info, "Using mmdb " + geoDB.get_lib_version_mmdb() + " and geolite2pp " +
            geoDB.get_lib_version_geolite2pp());

    try
    {
        boost::asio::io_context io_context;
        MT_Server server(log, geoDB, io_context, listening_port);
        io_context.run();
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    return EXIT_SUCCESS;
}

