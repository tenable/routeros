#include "logging.hpp"

#include <exception>
#include <iostream>
#include <sstream>
#include <ctime>

Logging::Logging(const std::string& p_logName) :
    m_logName(p_logName),
    m_fileStream()
{
}

Logging::~Logging()
{
    if (m_fileStream.is_open())
    {
        m_fileStream.close();
    }
}

void Logging::init()
{
    m_fileStream.open(m_logName);
    if (!m_fileStream.good())
    {
        throw std::runtime_error("Cannot open log file.");
    }
}

void Logging::log(logging::type p_type, const std::string& p_string)
{
    if (!m_logName.empty() && !m_fileStream.is_open())
    {
        init();
    }

    std::stringstream toLog;

    switch (p_type)
    {
        default:
        case logging::k_info:
            toLog << "[+] ";
            break;
        case logging::k_exciting:
            toLog << "[!] ";
            break;
        case logging::k_error:
            toLog << "[-] ";
            break;
    }

    // gen timestamp
    std::time_t t = std::time(0);
    std::tm* now = std::localtime(&t);
    toLog << (now->tm_year + 1900) << '-' 
          << (now->tm_mon + 1) << '-'
          << now->tm_mday << " "
          << now->tm_hour << ":"
          << now->tm_min << ":"
          << now->tm_sec << " | ";
    toLog << p_string;


    if (m_fileStream.is_open())
    {
        m_fileStream << toLog.str() << std::endl;
    }
    else
    {
        std::cout << toLog.str() << std::endl;
    }
}

void Logging::log(logging::type p_type, const std::string& p_ip, boost::uint16_t p_port, const std::string& p_string)
{
    std::stringstream make_ip_log;
    make_ip_log << p_ip << " | " << p_port << " | " << p_string;
    log(p_type, make_ip_log.str());
}