#include <cstdlib>
#include <pcap.h>
#include <string>
#include <iostream>
#include <boost/lexical_cast.hpp>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>

#include "winbox_message.hpp"

namespace
{
    const char s_version[] = "Winbox Decrypt PCAP Decrypt 1.0.0";

    bool parseCommandLine(int p_argCount, const char* p_argArray[],
                          std::string& p_file)
    {
        boost::program_options::options_description description("options");
        description.add_options()
        ("help", "A list of command line options")
        ("version", "Display version information")
        ("file,f", boost::program_options::value<std::string>(),
         "The pcap with the jsproxy login to examine");

        boost::program_options::variables_map argv_map;
        try {
            boost::program_options::store(
                boost::program_options::parse_command_line(
                    p_argCount, p_argArray, description), argv_map);
        }
        catch (const std::exception& e) {
            std::cerr << e.what() << "\n" << std::endl;
            std::cout << description << std::endl;
            return false;
        }

        boost::program_options::notify(argv_map);
        if (argv_map.empty() || argv_map.count("help")) {
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
        else
        {
            std::cout << description << std::endl;
        }

        return false;
    }
}

void parse_string(std::string& p_data, bool p_server)
{
    while (p_data.size() > 6)
    {
        std::string data(p_data);
        boost::uint16_t advertised_length = (data[2] & 0xff) << 8 | (data[3] & 0xff);

        if (data.size() < (advertised_length + 4))
        {
            // the parser doesn't handle the case where an incomplete message
            // is passed here
            p_data.clear();
            return;
        }

        if ((data[0] & 0xff) == 0xff)
        {
            // special logic to erase ffs
            for (std::size_t i = 0x101; i < data.size(); i += 0xff)
            {
                if (static_cast<unsigned char>(data[i+1]) != 0xff)
                {
                    break;
                }
                data.erase(i, 2);
            }
        }

        if (data.size() > (advertised_length + 4))
        {
            data.resize(advertised_length + 4);
        }

        if (data[4] != 'M' || data[5] != '2')
        {
            std::cerr << "Server side parsing error." << std::endl;
            return;
        }

        data.erase(0, 6);
        WinboxMessage msg;
        msg.parse_binary(data);
        if (p_server)
        {
            std::cout << "<- ";
        }
        else
        {
            std::cout << "-> ";
        }
        std::cout << msg.serialize_to_json() << std::endl;

        p_data.erase(0, advertised_length + 4);
    }
}

int main(int p_argc, const char** p_argv)
{
    std::string fileName;
    if (!parseCommandLine(p_argc, p_argv, fileName))
    {
        return EXIT_FAILURE;
    }

    std::cout << "Opening " << fileName << std::endl;
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* handle = pcap_open_offline(fileName.c_str(), errbuf);
    if (handle == NULL)
    {
        std::cerr << "Failed to open the pcap: " << errbuf << std::endl;
        return EXIT_FAILURE;
    }

    // read in the packets. Anything with a tcp payload hand to parser.
    const boost::uint8_t* packet = NULL;
    struct pcap_pkthdr header = { 0, 0, 0, 0};


    // this is terribad
    std::map<bool, std::string> buffer;

    while ((packet = pcap_next(handle, &header)) != NULL)
    { 
        if (header.caplen != header.len)
        {
            // skip the truncated packet
            continue;
        }

        if (header.len <= 54)
        {
            // too little data for us to care
            continue;
        }

        boost::uint16_t etherType = (packet[12] << 8) | packet[13];
        if (etherType != 0x800)
        {
            // skip non ipv4
            continue;
        }

        // skip to the IPv4 header
        packet += 14;
        boost::uint16_t length = (packet[2] << 8) | packet[3];
        if (length > header.len)
        {
            // Bad length in IPv4 header
            continue;
        }

        if (packet[9] != 0x06)
        {
            // Skipping non-TCP packet.
            continue;
        }

        boost::uint16_t headerLength = (packet[0] & 0x0f) * 4;
        if ((headerLength + 20) > length)
        {
            // Bad header length in IPv4 header
            continue;
        }

        boost::uint32_t srcAddress = (packet[12] & 0xff) << 24 | (packet[13] & 0xff) 
            << 16 | (packet[14] & 0xff) << 8 | (packet[15] & 0xff);
        boost::uint32_t dstAddress = (packet[16] & 0xff) << 24 | (packet[17] & 0xff) 
            << 16 | (packet[18] & 0xff) << 8 | (packet[19] & 0xff);


        // skip to the TCP header
        packet += headerLength;
        length -= headerLength;

        headerLength = packet[12] >> 2;
        if (headerLength > length)
        {
            // Bad length in the TCP header
            continue;
        }

        boost::uint16_t sourcePort = (packet[0] & 0xff) << 8 | (packet[1] & 0xff);
        boost::uint16_t dstPort = (packet[2] & 0xff) << 8 | (packet[3] & 0xff);

        if (sourcePort != 8291 && dstPort != 8291)
        {
            continue;
        }

        // skip to the payload
        packet += headerLength;
        length -= headerLength;

        if (length == 0)
        {
            continue;
        }

        if (sourcePort == 8291)
        {
            buffer[true].append((const char*)packet, length);
            parse_string(buffer[false], false);
        }
        else
        {
            buffer[false].append((const char*)packet, length);
            parse_string(buffer[true], true);
        }
    }

    std::cout << "Done!" << std::endl << std::endl;
    pcap_close(handle);  //close the pcap file
    return EXIT_SUCCESS;
}
