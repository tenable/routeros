#ifndef SESSION_PARSER_HPP
#define SESSION_PARSER_HPP

#include <string>
#include <vector>
#include <boost/cstdint.hpp>

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
    SessionParser();
    ~SessionParser();

    bool loadPasswords(const std::string& p_passwordsPath);
    void parse(const boost::uint8_t* p_data, boost::uint16_t p_length, boost::uint32_t p_srcAddr);

private:

    boost::uint32_t m_serverAddress;
    session_state m_state;
    std::string m_username;

    //crypto values
    std::string m_lchallenge;
    std::string m_rchallenge;
    std::string m_response;
    std::string m_response1;
    std::string m_response2;
    std::string m_response3;

    //all the loaded passwords
    std::vector<std::string> m_passwords;
};

#endif