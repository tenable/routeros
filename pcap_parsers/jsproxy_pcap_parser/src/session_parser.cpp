#include "session_parser.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <boost/regex.hpp>
#include <boost/lexical_cast.hpp>
#include <arpa/inet.h>

#include "md4.hpp"
#include "des.hpp"
#include "sha1.hpp"
#include "winbox_message.hpp"

namespace
{
    const std::string s_lchallenge("\x21\x40\x23\x24\x25\x5E\x26\x2A\x28\x29\x5F\x2B\x3A\x33\x7C\x7E");
    const std::string s_padding("        ");

    char from_hex(char ch)
    {
        return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
    }

    std::string url_decode(const std::string& text)
    {
        char h;
        std::stringstream escaped;
        escaped.fill('0');

        for (auto i = text.begin(), n = text.end(); i != n; ++i) {
            std::string::value_type c = (*i);

            if (c == '%') {
                if (i[1] && i[2]) {
                    h = from_hex(i[1]) << 4 | from_hex(i[2]);
                    escaped << h;
                    i += 2;
                }
            } else if (c == '+') {
                escaped << ' ';
            } else {
                escaped << c;
            }
        }

        return escaped.str();
    }

    /*
     * Find the \r\n\r\n that denotes the end of the HTTP header and move the
     * provided string to just passed that location
     */
    bool moveToPayload(std::string& p_packet)
    {
        std::size_t offset = p_packet.find("\r\n\r\n");
        if (offset == std::string::npos) {
            return false;
        }
        p_packet.erase(0, offset + 4);
        return true;
    }

    boost::uint8_t codePointAt(const std::string& p_seq, std::size_t& p_index)
    {
        char c1 = p_seq[p_index];
        if (c1 & 0x80) {
            if ((c1 & 0xf0) != 0xc0) {
                throw std::runtime_error("Unhandled unicode size");
            }
            if ((p_index + 1) >= p_seq.length()) {
                throw std::runtime_error("Not enough data in the string");
            }
            p_index++;

            char high = c1 & 0x03;
            high = high << 6;

            char low = p_seq[p_index++] & 0x3f;
            return (high | low);
        }
        p_index++;
        return c1;
    }

    std::string fromCharCode(const std::string& p_seq)
    {
        std::string retval;

        for (std::size_t i = 0; i < p_seq.size(); i++) {
            char c = p_seq[i];
            if (c == 0) {
                // I'm not sure why this is a thing. Represent all zeros as 256.
                retval.push_back('\xc4');
                retval.push_back('\x80');
            } else if ((c & 0x80) == 0) {
                retval.push_back(c);
            } else {
                char c1_high = ((c & 0xc0) >> 6) & 0xff;
                c1_high = c1_high | 0xc0;
                retval.push_back(c1_high);

                char c1_low = (c & 0x3f) & 0xff;
                c1_low = c1_low | 0x80;
                retval.push_back(c1_low);
            }
        }
        return retval;
    }

    void printHexString(const std::string& p_string, bool p_endl=true)
    {
        for (std::size_t i = 0; i < p_string.length(); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << (static_cast<boost::uint32_t>(p_string[i]) & 0xff);
        }
        if (p_endl) {
            std::cout << std::endl;
        }
    }

    std::string hexToString(const std::string& p_string)
    {
        std::stringstream ss;
        for (std::size_t i = 0; i < p_string.length(); ++i)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (static_cast<boost::uint32_t>(p_string[i]) & 0xff);
        }
        return ss.str();
    }

    std::string createChallengeHash(const std::string p_rchallenge)
    {
        std::string challenge(s_lchallenge);
        challenge.append(p_rchallenge);
        challenge.append("admin");
        unsigned char result[20] = { 0 };
        sha1::calc(challenge.data(), challenge.size(), result);
        std::string challengeHash((char*)result, 20);
        challengeHash.resize(8);
        return challengeHash;
    }

    std::string weirdPasswordThing(const std::string& p_pass)
    {
        std::string retval;
        for (std::size_t i = 0; i < p_pass.size(); ) {
            retval.push_back(codePointAt(p_pass, i));
            retval.push_back('\x00');
        }
        return retval;
    }

    std::string makeDESKey(const std::string& p_hash, std::size_t j)
    {
        std::string retVal;
        for(std::size_t i = j; i < (j + 56); i += 7) {
            uint16_t w = p_hash[i >> 3];
            w <<= 8;
            w |= (p_hash[(i >> 3) + 1] & 0xff);
            retVal.push_back((w >> (8 - (i & 7))) & 0xfe);
        }
        return retVal;
    }

    std::string createResponse(const std::string& p_pwdHash, const std::string& p_challengeHash)
    {
        std::string paddedHash(p_pwdHash);
        paddedHash.resize(24, 0);
        std::string response;
        std::string encrypted;
        std::string desKey1(makeDESKey(paddedHash, 0));
        DES::des(p_challengeHash, desKey1, encrypted);
        response.append(encrypted);
        encrypted.clear();
        std::string desKey2(makeDESKey(paddedHash, 56));
        DES::des(p_challengeHash, desKey2, encrypted);
        response.append(encrypted);
        encrypted.clear();
        std::string desKey3(makeDESKey(paddedHash, 112));
        DES::des(p_challengeHash, desKey3, encrypted);
        response.append(encrypted);
        return response;
    }
}

SessionParser::SessionParser(std::string& p_username, std::string& p_password) :
    m_serverAddress(0),
    m_clientAddress(0),
    m_serverPort(0),
    m_clientPort(0),
    m_username(p_username),
    m_password(p_password),
    m_sessionID(),
    m_recvCount(1),
    m_sendCount(1),
    m_recvBuffer(),
    m_expected(0),
    m_clientBuffered(),
    m_serverBuffered(),
    m_state(k_none),
    m_rx(),
    m_tx()
{
}

SessionParser::~SessionParser()
{
}

void SessionParser::parse(const boost::uint8_t* p_data, boost::uint16_t p_length, boost::uint32_t p_srcAddr, boost::uint32_t p_destAddr, boost::uint16_t p_srcPort, boost::uint16_t p_destPort)
{
    switch(m_state) {
        case k_none:
            if (p_length > 24 && memcmp(p_data, "POST /jsproxy HTTP/1.1\r\n", 24) == 0)
            {
                std::string data(p_data, p_data + p_length);
                if (data.find("Content-Length: 0") == std::string::npos)
                {
                    // the first post should have no content
                    return;
                }
                std::cout << "[+] Found the initial request from " << std::hex << p_srcAddr << ":" << p_srcPort << " to " << p_destAddr << ":" <<  p_destPort << std::endl;
                m_serverAddress = p_destAddr;
                m_serverPort = p_destPort;
                m_clientAddress = p_srcAddr;
                m_clientPort = p_srcPort;
                m_state = k_challenge;
            }
            break;
        case k_challenge:
            if (m_serverAddress == p_srcAddr && m_serverPort == p_srcPort &&
                m_clientAddress == p_destAddr && m_clientPort == p_destPort &&
                p_length > 17 && memcmp(p_data, "HTTP/1.1 200 OK\r\n", 17) == 0)
            {
                std::string message(p_data, p_data + p_length);
                if (moveToPayload(message) == false)
                {
                    return;
                }

                std::size_t index = 0;
                for (std::size_t i = 0; i < 4; i++)
                {
                    int codePoint = codePointAt(message, index) & 0xff;
                    m_sessionID.push_back(codePoint);
                }
                std::cout << "[+] Found the session ID: ";
                printHexString(m_sessionID);

                // no idea what these four are
                for (std::size_t i = 0; i < 4; i++) {
                    codePointAt(message, index) & 0xff;
                }

                // extract the 16 byte challenge
                std::string rchallenge;
                for ( ; index < message.length(); ) {
                    int codePoint = codePointAt(message, index) & 0xff;
                    rchallenge.push_back(codePoint);
                }
                if (rchallenge.size() != 16) {
                    return;
                }
                std::cout << "[+] Found the 16 byte challenge: ";
                printHexString(rchallenge);

                // create the challenge hash
                std::string challengeHash(createChallengeHash(rchallenge));

                // generate the password hashes
                std::string pwdHash(MD4::md4(weirdPasswordThing(m_password)));
                std::string pwdHashHash(MD4::md4(pwdHash));

                // generate the challenge response
                std::string response(createResponse(pwdHash, challengeHash));

                // create the master key
                generateMasterKey(pwdHashHash, response);

                m_state = k_challenge_response;                
            }
            break;
        case k_challenge_response:
            if (m_serverAddress == p_destAddr && m_serverPort == p_destPort &&
                m_clientAddress == p_srcAddr &&
                p_length > 24 &&  memcmp(p_data, "POST /jsproxy HTTP/1.1\r\n", 24) == 0)
            {
                std::cout << "[+] Found the challenge response" << std::endl;
                m_state = k_decrypt;
            }
            break;
        case k_decrypt:
            // note that it looks like we start sending from multiple ports so don't check that
            if (m_serverAddress == p_destAddr && m_serverPort == p_destPort &&
                m_clientAddress == p_srcAddr &&
                p_length > 15 &&  memcmp(p_data, "GET /jsproxy/?%", 15) == 0)
            {
                std::string message(p_data + 14, p_data + p_length - 14);
                std::size_t eol = message.find(" HTTP/1.1\r\n");
                if (eol == std::string::npos)
                {
                    return;
                }
                message.erase(eol);

                message = url_decode(message);

                std::size_t index = 0;
                std::string id;
                for (std::size_t i = 0; i < 4; i++) {
                    int codePoint = codePointAt(message, index);
                    id.push_back(codePoint);
                }

                std::string sequence;
                for (std::size_t i = 0; i < 4; i++) {
                    int codePoint = codePointAt(message, index);
                    sequence.push_back(codePoint);
                }

                std::string hex("0x");
                hex.append(hexToString(sequence));
                boost::uint32_t seq = strtol(hex.c_str(), NULL, 16);

                std::string converted;
                for ( ; index < message.length(); ) {
                    int codePoint = codePointAt(message, index) & 0xff;
                    converted.push_back(codePoint);
                }

                m_recvCount += converted.length();

                std::cout << " -> ";
                std::cout << m_tx.decrypt(converted, 0) << std::endl;
            }
            else if (p_length > 22 && memcmp(p_data, "HTTP/1.1 404 Not Found", 22) == 0)
            {
            }
            else if (m_serverAddress == p_destAddr && m_serverPort == p_destPort &&
                m_clientAddress == p_srcAddr &&
                p_length > 24 && memcmp(p_data, "POST /jsproxy HTTP/1.1\r\n", 24) == 0)
            {

                // extract the content length
                boost::uint32_t length = 0;
                std::string message(p_data, p_data + p_length);
                boost::regex content_length{"Content-Length: (\\d+)"};
                boost::smatch what;
                if (boost::regex_search(message, what, content_length))
                {
                    length = boost::lexical_cast<boost::uint32_t>(what[1]);
                }
                else
                {
                    return;
                }

                bool convert = true;
                if (message.find("Content-Type: msg\r\n") != std::string::npos)
                {
                    convert = false;
                }
                else if (message.find("Content-Type: text/plain") == std::string::npos)
                {
                    return;
                }

                if (moveToPayload(message) == false)
                {
                    return;
                }

                if (message.length() != length)
                {
                    std::cout << "FIX ME!" << std::endl;
                    exit(0);
                }

                // skip the first 8 bytes [4 bytes id][4 bytes sequence] where sequence is len(payload) + 8
                if (convert)
                {
                    std::size_t index = 0;
                    std::string id;
                    for (std::size_t i = 0; i < 4; i++) {
                        int codePoint = codePointAt(message, index);
                        id.push_back(codePoint);
                    }

                    if (id != m_sessionID)
                    {
                        return;
                    }

                    std::string sequence;
                    for (std::size_t i = 0; i < 4; i++) {
                        int codePoint = codePointAt(message, index);
                        sequence.push_back(codePoint);
                    }

                    std::string hex("0x");
                    hex.append(hexToString(sequence));
                    boost::uint32_t seq = strtol(hex.c_str(), NULL, 16);

                    std::string converted;
                    for ( ; index < message.length(); ) {
                        int codePoint = codePointAt(message, index) & 0xff;
                        converted.push_back(codePoint);
                    }

                    if (seq != m_recvCount)
                    {
                        m_clientBuffered[seq] = converted;
                    }
                    else
                    {
                        m_recvCount += converted.length();

                        std::cout << " -> ";
                        std::cout << m_tx.decrypt(converted, 0) << std::endl;
                    }

                    for (std::map<boost::uint32_t,std::string>::iterator it = m_clientBuffered.begin();
                         it != m_clientBuffered.end(); ++it)
                    {
                        if (it->first == m_recvCount)
                        {
                            std::string buffered(m_tx.decrypt(it->second, 0));
                            if (buffered[0] == '{')
                            {
                                std::cout << " -> ";
                                m_recvCount += (it->second.length());
                                std::cout << buffered << std::endl;
                            }
                        }
                    }
                }
                else
                {
                    boost::uint32_t id = 0;
                    memcpy(&id, &message[0], 4);
                    boost::uint32_t seq = 0;
                    memcpy(&seq, &message[4], 4);
                    message.erase(0,8);

                    seq = ntohl(seq);
                    if (seq != m_recvCount)
                    {
                        m_clientBuffered[seq] = message;
                    }
                    else
                    {                                  
                        std::string binary_decrypted(m_tx.decrypt(message, 0));
                        if (binary_decrypted[0] != 'M' || binary_decrypted[1] != '2')
                        {
                            std::cerr << "buffering broke." << std::endl;
                            exit(0);
                        }
                        m_recvCount += message.size();
                        binary_decrypted.erase(0, 2);
                        WinboxMessage msg;
                        msg.parse_binary(binary_decrypted);
                        std::cout << "-> " << msg.serialize_to_json() << std::endl;
                    }

                    for (std::map<boost::uint32_t,std::string>::iterator it = m_clientBuffered.begin();
                         it != m_clientBuffered.end(); ++it)
                    {
                        if (it->first == m_recvCount)
                        {
                            std::string binary_decrypted(m_tx.decrypt(it->second, 0));
                            if (binary_decrypted[0] != 'M' || binary_decrypted[1] != '2')
                            {
                                std::cerr << "buffering broke." << std::endl;
                                exit(0);
                            }
                            m_recvCount += it->second.size();
                            binary_decrypted.erase(0, 2);
                            WinboxMessage msg;
                            msg.parse_binary(binary_decrypted);
                            std::cout << "-> " << msg.serialize_to_json() << std::endl;
                        }
                    }
                }
            }
            else if (m_serverAddress == p_srcAddr && m_serverPort == p_srcPort &&
                m_clientAddress == p_destAddr &&
                p_length > 17 && memcmp(p_data, "HTTP/1.1 200 OK\r\n", 17) == 0)
            {
                bool convert = true;
                std::string message(p_data, p_data + p_length);
                if (message.find("Content-Type: msg\r\n") != std::string::npos)
                {
                    convert = false;
                }
                else if (message.find("Content-Type: text/plain") == std::string::npos)
                {
                    return;
                }

                // extract the content length
                boost::uint32_t length = 0;
                boost::regex content_length{"Content-Length: (\\d+)"};
                boost::smatch what;
                if (boost::regex_search(message, what, content_length))
                {
                    length = boost::lexical_cast<boost::uint32_t>(what[1]);
                }
                else
                {
                    return;
                }

                if (moveToPayload(message) == false)
                {
                    return;
                }

                if (message.length() != length)
                {
                    m_recvBuffer.assign(message);
                    m_expected = length;
                    return;
                }

                // skip the first 8 bytes [4 bytes id][4 bytes sequence] where sequence is len(payload) + 8
                if (convert)
                {
                    std::size_t index = 0;
                    std::string id;
                    for (std::size_t i = 0; i < 4; i++) {
                        int codePoint = codePointAt(message, index);
                        id.push_back(codePoint);
                    }

                    std::string sequence;
                    for (std::size_t i = 0; i < 4; i++) {
                        int codePoint = codePointAt(message, index);
                        sequence.push_back(codePoint);
                    }


                    std::string hex("0x");
                    hex.append(hexToString(sequence));
                    boost::uint32_t seq = strtol(hex.c_str(), NULL, 16);

                    std::string converted;
                    for ( ; index < message.length(); ) {
                        int codePoint = codePointAt(message, index) & 0xff;
                        converted.push_back(codePoint);
                    }

                    if (seq != m_sendCount)
                    {
                        m_serverBuffered[seq] = converted;
                    }
                    else
                    {
                        m_sendCount += converted.length();

                        std::cout << " <- ";
                        std::cout << m_rx.decrypt(converted, 0) << std::endl;
                    }

                    for (std::map<boost::uint32_t,std::string>::iterator it = m_serverBuffered.begin();
                         it != m_serverBuffered.end(); ++it)
                    {
                        if (it->first == m_sendCount)
                        {
                            //m_recvCount += it->second.length();
                            std::string buffered(m_rx.decrypt(it->second, 0));
                            if (buffered[0] == '{')
                            {
                                std::cout << " -> ";
                                m_sendCount += (it->second.length());
                                std::cout << buffered << std::endl;
                            }
                        }
                    }
                }
                else
                {
                    message.erase(0,8);
                    std::string binary_decrypted(m_rx.decrypt(message, 0));
                    WinboxMessage msg;
                    msg.parse_binary(binary_decrypted);
                    std::cout << "<- " << msg.serialize_to_json() << std::endl;
                }
            }
            else if (m_serverAddress == p_srcAddr && m_serverPort == p_srcPort &&
                m_clientAddress == p_destAddr &&
                p_length > 4 && memcmp(p_data, "HTTP", 4) != 0 &&
                m_expected != 0)
            {
                m_recvBuffer.append(p_data, p_data + p_length);
                if (m_expected < m_recvBuffer.length())
                {
                    std::cout << "whoa there buddy" << std::endl;
                    exit(1);
                }
                else if (m_expected > m_recvBuffer.length())
                {
                    return;
                }
                std::size_t index = 0;
                std::string id;
                for (std::size_t i = 0; i < 4; i++) {
                    int codePoint = codePointAt(m_recvBuffer, index);
                    id.push_back(codePoint);
                }

                std::string sequence;
                for (std::size_t i = 0; i < 4; i++) {
                    int codePoint = codePointAt(m_recvBuffer, index);
                    sequence.push_back(codePoint);
                }

                std::string converted;
                for ( ; index < m_recvBuffer.length(); ) {
                    int codePoint = codePointAt(m_recvBuffer, index) & 0xff;
                    converted.push_back(codePoint);
                }

                m_sendCount += converted.length();

                std::cout << " <- ";
                std::cout << m_rx.decrypt(converted, 0) << std::endl;

                m_recvBuffer.clear();
                m_expected = 0;

                for (std::map<boost::uint32_t,std::string>::iterator it = m_serverBuffered.begin();
                     it != m_serverBuffered.end(); ++it)
                {
                    if (it->first == m_sendCount)
                    {
                        //m_recvCount += it->second.length();
                        std::string buffered(m_rx.decrypt(it->second, 0));
                        if (buffered[0] == '{')
                        {
                            std::cout << " -> ";
                            m_sendCount += (it->second.length());
                            std::cout << buffered << std::endl;
                        }
                    }
                }
            }
            break;
        case k_done:
        default:
            break;
    }
}

void SessionParser::generateMasterKey(const std::string& p_pwdHashHash, const std::string& p_response)
{
    std::string masterKey(p_pwdHashHash);
    masterKey.append(p_response);
    masterKey.append("This is the MPPE Master Key");

    unsigned char sharesult[20] = { 0 };
    sha1::calc(masterKey.data(), masterKey.size(), sharesult);
    masterKey.assign((char*)sharesult, 16);

    std::cout << "[+] Generated the Master Key: ";
    printHexString(masterKey);

    // generate the send and receive RC4 contexts
    for (int i = 0; i < 40; ++i) {
        masterKey.push_back(0);
    }

    std::string server_key(masterKey);
    server_key.append("On the client side, this is the receive key; on the server side, it is the send key.");
    for (int i = 0; i < 40; ++i) {
        server_key.push_back(0xf2);
    }
    unsigned char serversha[20] = { 0 };
    sha1::calc(server_key.data(), server_key.size(), serversha);
    server_key.assign((char*)serversha, 16);


    std::cout << "[+] Generated the Server Key: ";
    printHexString(server_key);

    m_rx.setKey(server_key);

    std::string client_key(masterKey);
    client_key.append("On the client side, this is the send key; on the server side, it is the receive key.");
    for (int i = 0; i < 40; ++i) {
        client_key.push_back(0xf2);
    }
    unsigned char clientsha[20] = { 0 };
    sha1::calc(client_key.data(), client_key.size(), clientsha);
    client_key.assign((char*)clientsha, 16);

    std::cout << "[+] Generated the Client Key: ";
    printHexString(client_key);

    m_tx.setKey(client_key);
}
