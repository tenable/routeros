/*
    Copyright 2019 Tenable, Inc.

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
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <boost/uuid/sha1.hpp>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>

namespace
{
    const char s_version[] = "List NPK 1.0";

    bool parseCommandLine(int p_argCount, const char* p_argArray[], std::string& p_npk_file_path)
    {
        boost::program_options::options_description description("options");
        description.add_options()
        ("help,h", "A list of command line options")
        ("version,v", "Display version information")
        ("file,f", boost::program_options::value<std::string>(), "The npk file to read");

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
    
        if (argv_map.count("file"))
        {
            p_npk_file_path.assign(argv_map["file"].as<std::string>());
            return true;
        }
        else
        {
            std::cout << description << std::endl;
        }

        return false;
    }

    std::string section_name(boost::uint32_t p_type)
    {
        switch (p_type)
        {
            case 1:
                return "part info";
            case 2:
                return "part description";
            case 3:
                return "dependencies";
            case 4:
                return "file container";
            case 5:
                return "install script [libinstall]";
            case 6:
                return "uninstall script [libinstall]";
            case 7:
                return "install script [bash]";
            case 8:
                return "uninstall script [bash]";
            case 9:
                return "signature";
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
                return "unused";
            case 16:
                return "architecture";
            case 17:
                return "package conflicts";
            case 18:
                return "package info";
            case 19:
                return "part features";
            case 20:
                return "package features";
            case 21:
                return "squashfs block";
            case 22:
                return "zero padding";
            case 23:
                return "digest";
            case 24:
                return "channel";
            default:
                break;
        }
        return "unknown section";
    }
}

int main(int p_argc, const char** p_argv)
{
    std::string npk_file_path;
    if (parseCommandLine(p_argc, p_argv, npk_file_path) == false)
    {
        return EXIT_FAILURE;
    }

    std::ifstream npk_file(npk_file_path, std::ifstream::in | std::ifstream::binary);
    if (!npk_file.is_open() || !npk_file.good())
    {
        std::cerr << "Failed to open the npk file " << npk_file_path << std::endl;
        return EXIT_FAILURE;
    }

    std::string npk_data((std::istreambuf_iterator<char>(npk_file)), std::istreambuf_iterator<char>());

    npk_file.close();

    if (npk_data.size() < 8)
    {
        std::cerr << "Not enough data to read in file header." << std::endl;
        return EXIT_FAILURE;
    }

    boost::uint32_t magic = *reinterpret_cast<const boost::uint32_t*>(npk_data.data());
    boost::uint32_t size = *reinterpret_cast<const boost::uint32_t*>(npk_data.data() + 4);
    if (magic != 0xbad0f11e)
    {
        std::cerr << "Bad magic: " << std::hex << magic << std::endl;
        return EXIT_FAILURE;
    }

    if ((size + 8) != npk_data.size())
    {
        std::cerr << "Invalid total size: " << std::dec << size << " vs " << npk_data.size() << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "total size: " << size + 8 << std::endl;
    std::cout << "-----------" << std::endl;;

    npk_data.erase(0, 8);

    std::size_t i = 0;
    std::size_t offset = 8;
    boost::uuids::detail::sha1 lol;
    while (npk_data.size() > 7)
    {
        
        boost::uint16_t type = *reinterpret_cast<boost::uint16_t*>(npk_data.data());
        boost::uint32_t part_size = *reinterpret_cast<boost::uint32_t*>(npk_data.data() + 2);

        lol.process_bytes(npk_data.data(), 6);

        npk_data.erase(0, 6);

        if (part_size > npk_data.size())
        {
            std::cerr << "Invalid part size" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << i << ": (" << type << ") " << section_name(type) << ", size = " << part_size << ", offset = " << std::hex << offset << std::dec;

        if (type == 1)
        {
            std::cout << " -> " << npk_data.c_str();
        }
        std::cout << std::endl;

        if (type != 9)
        {
            lol.process_bytes(npk_data.data(), part_size);
        }
        else
        {
            std::cout << "sha1: ";
            unsigned int digest[5] = { 0 };
            lol.get_digest(digest);
            for(int i = 0; i < 5; ++i)
            {
                std::cout << std::hex << std::setfill('0') << std::setw(8) << digest[i];
            }
            std::cout << std::endl;
            lol = boost::uuids::detail::sha1();
        }
        npk_data.erase(0, part_size);
        offset += part_size;
        ++i;
    }

    return EXIT_SUCCESS;
}
