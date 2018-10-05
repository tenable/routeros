#ifndef SESSION_PARSER_HPP
#define SESSION_PARSER_HPP

#include <string>
#include <map>
#include <boost/cstdint.hpp>

#include "rc4.hpp"

class SessionParser
{
private:

    enum session_state {
        k_none,
        k_request,
        k_challenge,
        k_challenge_response,
        k_decrypt,
        k_done
    };

public:
    SessionParser(std::string& p_username, std::string& p_password);
    ~SessionParser();

    void parse(const boost::uint8_t* p_data, boost::uint16_t p_length, boost::uint32_t p_srcAddr,
               boost::uint32_t p_destAddr, boost::uint16_t p_srcPort, boost::uint16_t p_destPrt);

private:
    void generateMasterKey(const std::string& p_pwdHashHash, const std::string& p_response);

private:

    boost::uint32_t m_serverAddress;
    boost::uint32_t m_clientAddress;
    boost::uint16_t m_serverPort;
    boost::uint16_t m_clientPort;

    std::string m_username;
    std::string m_password;

    std::string m_sessionID;
    boost::uint32_t m_recvCount;
    boost::uint32_t m_sendCount;

    std::string m_recvBuffer;
    boost::uint32_t m_expected;

    std::map<boost::uint32_t, std::string> m_clientBuffered;
    std::map<boost::uint32_t, std::string> m_serverBuffered;

    session_state m_state;

    RC4 m_rx;
    RC4 m_tx;

};

#endif