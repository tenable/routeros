#include <cstdlib>
#include <pcap.h>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>

#include "session_parser.hpp"

namespace
{
    const char s_version[] = "JSProxy Password Bruteforce version 1.0.0";

    bool parseCommandLine(int p_argCount, const char* p_argArray[],
                          std::string& p_file, std::string& p_passwords)
    {
        boost::program_options::options_description description("options");
        description.add_options()
        ("help", "A list of command line options")
        ("version", "Display version information")
        ("passwords,p", boost::program_options::value<std::string>(), "A password list file. Each on their own line.")
        ("file,f", boost::program_options::value<std::string>(), "The pcap with the jsproxy login to examine");

        boost::program_options::variables_map argv_map;
        try
        {
            boost::program_options::store(
                boost::program_options::parse_command_line(
                    p_argCount, p_argArray, description), argv_map);
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

        if (argv_map.count("file") && argv_map.count("passwords"))
        {
            p_file.assign(argv_map["file"].as<std::string>());
            p_passwords.assign(argv_map["passwords"].as<std::string>());
            return true;
        }
        else
        {
            std::cerr << description << std::endl;
        }

        return false;
    }
}

int main(int p_argc, const char** p_argv)
{
    std::string fileName;
    std::string passwords;
    if (!parseCommandLine(p_argc, p_argv, fileName, passwords))
    {
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* handle = pcap_open_offline(fileName.c_str(), errbuf);
    if (handle == NULL)
    {
        std::cerr << "Failed to find the pcap file." << std::endl;
        return EXIT_FAILURE;
    }

    SessionParser parser;
    if (!parser.loadPasswords(passwords))
    {
        return EXIT_FAILURE;
    }

    // read in the packets. Anything with a tcp payload hand to parser.
    const boost::uint8_t* packet = NULL;
    struct pcap_pkthdr header = { 0, 0, 0, 0};
    while ((packet = pcap_next(handle, &header)) != NULL)
    { 
        if (header.caplen != header.len)
        {
            std::cerr << "Skipping truncated packet." << std::endl;
            continue;
        }

        if (header.len <= 54)
        {
            std::cerr << "Skipping uninteresting packet." << std::endl;
            continue;
        }

        boost::uint16_t etherType = (packet[12] << 8) | packet[13];
        if (etherType != 0x800)
        {
            std::cerr << "Skipping non-IPv4 packet." << std::endl;
            continue;
        }

        // skip to the IPv4 header
        packet += 14;
        boost::uint16_t length = (packet[2] << 8) | packet[3];
        if (length > header.len)
        {
            std::cerr << "Bad length in IPv4 header." << std::endl;
            continue;
        }

        if (packet[9] != 0x06)
        {
            std::cerr << "Skipping non-TCP packet." << std::endl;
            continue;
        }

        boost::uint32_t srcAddress = (packet[12] & 0xff) << 24 | (packet[13] & 0xff) 
            << 16 | (packet[14] & 0xff) << 8 | (packet[15] & 0xff);
        boost::uint16_t headerLength = (packet[0] & 0x0f) * 4;
        if ((headerLength + 20) > length)
        {
            std::cerr << "Bad header length in IPv4 header." << std::endl;
            continue;
        }

        // skip to the TCP header
        packet += headerLength;
        length -= headerLength;
        headerLength = packet[12] >> 2;
        if (headerLength > length)
        {
            std::cerr << "Bad length in the TCP header. " <<  std::endl;
            continue;
        }

        // skip to the payload
        packet += headerLength;
        length -= headerLength;
        if (length == 0)
        {
            continue;
        }
        parser.parse(packet, length, srcAddress);
    }

    pcap_close(handle);  //close the pcap file
    return EXIT_SUCCESS;
}
