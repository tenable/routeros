#include <fstream>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/scoped_array.hpp>
#include <boost/program_options.hpp>

namespace
{
    const char s_version[] = "x3 parser version 1.0.0";

    // at least need room for the header
    const boost::uint32_t s_minFileSize = 12;

    // this isn't actually a hard limit, but larger sizes are unexpected
    const boost::uint32_t s_maxFileSize = 100000;

    struct x3_header
    {
        // total length is the file size - 4 bytes (ie. itself)
        boost::uint32_t m_totalLength;

        // unused?
        boost::uint32_t m_reserved0;

        // unused?
        boost::uint32_t m_reserved1;
    };

    struct x3_entry
    {
        boost::uint32_t m_length;
        boost::uint32_t m_type;
    };

    bool parseCommandLine(int p_argCount, const char* p_argArray[], std::string& p_file)
    {
        boost::program_options::options_description description("options");
        description.add_options()
            ("help,h", "A list of command line options")
            ("version,v", "Display version information")
            ("file,f", boost::program_options::value<std::string>(), "The file to parse");

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
            std::cout << description << std::endl;
            return false;
        }

        boost::program_options::notify(argv_map);
        if (argv_map.empty() || argv_map.count("help"))
        {
            std::cout << description << std::endl;
            return false;
        }

        if (argv_map.count("version"))
        {
            std::cout << "Version: " << ::s_version << std::endl;
            return false;
        }

        if (argv_map.count("file"))
        {
            p_file.assign(argv_map["file"].as<std::string>());
            return true;
        }

        return false;
    }
}

int main(int p_argc, const char** p_argv)
{
    std::string file;
    if (!parseCommandLine(p_argc, p_argv, file))
    {
        return EXIT_FAILURE;
    }

    std::ifstream fileStream(file, std::ios::in | std::ios::binary | std::ios::ate);
    if (!fileStream.is_open())
    {
        std::cerr << "Failed to open " << file << std::endl;
        return EXIT_FAILURE;
    }

    std::streampos fileSize = fileStream.tellg();
    if (fileSize < s_minFileSize || fileSize > s_maxFileSize)
    {
        std::cerr << "Bad file size: " << fileSize << std::endl;
        fileStream.close();
        return EXIT_FAILURE;
    }

    // read the file into an array
    boost::scoped_array<char> memblock(new char[fileSize]);
    fileStream.seekg(0, std::ios::beg);
    fileStream.read(memblock.get(), fileSize);
    fileStream.close();

    const x3_header* head = reinterpret_cast<const x3_header*>(memblock.get());
    if (head->m_totalLength != (static_cast<boost::uint32_t>(fileSize) - 4))
    {
        std::cerr << "Invalid total size." << std::endl;
        return EXIT_FAILURE;
    }

    const char* memoryEnd = memblock.get() + fileSize;
    const char* memoryCurrent = memblock.get() + 12;

    for (const x3_entry* entry = reinterpret_cast<const x3_entry*>(memoryCurrent);
         (reinterpret_cast<const char*>(entry) + 12) < memoryEnd;
         memoryCurrent += entry->m_length + 4, entry = reinterpret_cast<const x3_entry*>(memoryCurrent))
    {
        // the outter entry should always be of type 0x1e
        if (entry->m_type != 0x1e)
        {
            std::cerr << "Parsing error." << std::endl;
            return EXIT_FAILURE;
        }

        for (const x3_entry* inner_entry = reinterpret_cast<const x3_entry*>(memoryCurrent + 12);
            reinterpret_cast<const char*>(inner_entry) < (memoryCurrent + entry->m_length + 4);
             inner_entry = reinterpret_cast<const x3_entry*>(reinterpret_cast<const char*>(inner_entry) + inner_entry->m_length + 4))
        {
            switch (inner_entry->m_type)
            {
            case 0x04: // the router number
                {
                    const char* route = reinterpret_cast<const char*>(inner_entry) + inner_entry->m_length;
                    std::cout << ",";
                    for (boost::uint8_t i = 0; i < 4; i++)
                    {
                        if (route[i] != 0)
                        {
                            std::cout << route[i];
                        }
                    }
                    std::cout << std::endl;
                }
                break;
            case 0x07: // the binary name
                {
                    std::string path(reinterpret_cast<const char*>(inner_entry) + 20, inner_entry->m_length - 16);
                    std::cout << path;
                }
                break;
            default:
                break;
            }
        }
    }

    return EXIT_SUCCESS;
}
