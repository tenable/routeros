#include "session.hpp"

#include <string>

Session::Session(const std::string& p_ip, const std::string& p_port) :
    m_ip(p_ip),
    m_port(p_port)
{

}

Session::~Session()
{
}
