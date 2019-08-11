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
#include <fstream>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>

namespace
{
    const char s_version[] = "Modify NPK 1.0";

    bool parseCommandLine(int p_argCount, const char* p_argArray[],
        std::string& p_npk_file_path, std::string& p_squashfs, std::string& p_name)
    {
        boost::program_options::options_description description("options");
        description.add_options()
        ("help,h", "A list of command line options")
        ("version,v", "Display version information")
        ("file,f", boost::program_options::value<std::string>(), "The npk file to manipulate")
        ("squash,s", boost::program_options::value<std::string>(), "The squashfs to insert")
        ("name,n", boost::program_options::value<std::string>(), "The new name of the package");

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
    
        if (argv_map.count("file") && argv_map.count("squash") && argv_map.count("name"))
        {
            p_npk_file_path.assign(argv_map["file"].as<std::string>());
            p_squashfs.assign(argv_map["squash"].as<std::string>());
            p_name.assign(argv_map["name"].as<std::string>());
            if (p_name.size() > 15)
            {
                std::cerr << "Name is too large to fit in package data structures." << std::endl;
                return false;
            }
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
    std::string npk_file_path;
    std::string squashfs_path;
    std::string package_name;
    if (parseCommandLine(p_argc, p_argv, npk_file_path, squashfs_path, package_name) == false)
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

    std::ifstream squash_file(squashfs_path, std::ifstream::in | std::ifstream::binary);
    if (!squash_file.is_open() || !squash_file.good())
    {
        std::cerr << "Failed to open the squash file " << squashfs_path << std::endl;
        return EXIT_FAILURE;
    }

    std::string squash_data((std::istreambuf_iterator<char>(squash_file)), std::istreambuf_iterator<char>());

    squash_file.close();

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

    npk_data.erase(0, 8);

    std::vector<std::pair<boost::uint16_t, std::string> > parts;
    while (npk_data.size() > 6)
    {
        boost::uint16_t type = *reinterpret_cast<boost::uint16_t*>(npk_data.data());
        boost::uint32_t part_size = *reinterpret_cast<boost::uint32_t*>(npk_data.data() + 2);
        npk_data.erase(0, 6);

        if (part_size > npk_data.size())
        {
            std::cerr << "Invalid part size" << std::endl;
            return EXIT_FAILURE;
        }

        // store the part
        if (type == 0x15 && part_size > 0)
        {
            //technically speaking, it looks like MT pads this with zeroes
            //until an 0x1000 boundary, but the VM doesn't seem to care?
            parts.push_back(std::make_pair(type, squash_data));
        }
        else if (type == 1 && part_size> 16)
        {
            // name is a fix size 16 byte field. Overwrite it and drop in our new name
            memset(&npk_data[0], 0, 16);
            memcpy(&npk_data[0], &package_name[0], package_name.size());
            parts.push_back(std::make_pair(type, std::string(npk_data.data(), part_size)));
        }
        else
        {
            parts.push_back(std::make_pair(type, std::string(npk_data.data(), part_size)));
        }

        npk_data.erase(0, part_size);
    }

    // recombine into a single string
    std::string output;
    for (std::size_t i = 0; i < parts.size(); i++)
    {
        boost::uint16_t part_type = parts[i].first;
        std::string& part_data(parts[i].second);
        boost::uint32_t part_size = part_data.size();

        std::string header;
        header.resize(6, 0);

        memcpy(&header[0], &part_type, 2);
        memcpy(&header[2], &part_size, 4);

        output.append(header);
        output.append(part_data);
    }

    // attach the trailing remainder
    output.append(npk_data);

    std::string output_header;
    output_header.resize(8, 0);

    boost::uint32_t magic_bytes = 0xbad0f11e;
    boost::uint32_t total_size = output.size() + 1;
    memcpy(&output_header[0], &magic_bytes, 4);
    memcpy(&output_header[4], &total_size, 4);
    output_header.append(output);

    std::ofstream outputFile(package_name + ".npk", std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);
    if (!outputFile.is_open() || !outputFile.good())
    {
        std::cout << "Failed to open the output file" << std::endl;
        return EXIT_FAILURE;
    }

    outputFile.write(output_header.data(), output_header.size());
    outputFile.close();

    return EXIT_SUCCESS;
}
