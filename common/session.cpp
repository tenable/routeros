#include "session.hpp"

#include <string>

#include <boost/lambda/bind.hpp>
#include <boost/lambda/lambda.hpp>


Session::Session(const std::string& p_ip, const std::string& p_port) :
    m_ip(p_ip),
    m_port(p_port),
    m_io_service(),
    m_socket(m_io_service),
    m_deadline(m_io_service)
{
    m_deadline.expires_at(boost::posix_time::pos_infin);
    check_deadline();
}

Session::~Session()
{
    close();
}

bool Session::connect()
{
    try
    {
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(m_ip), atoi(m_port.c_str()));

        // set a 2 second deadline for the connection   
        boost::system::error_code ec = boost::asio::error::would_block;
        m_deadline.expires_from_now(boost::posix_time::seconds(2));
        m_socket.async_connect(endpoint, boost::lambda::var(ec) = boost::lambda::_1);

        do
        {
            m_io_service.run_one();
        }
        while (ec == boost::asio::error::would_block);

        if (ec || !m_socket.is_open())
        {
           return false;
        }
    }
    catch(const std::exception& e)
    {
        return false;
    }
    return true;
}

void Session::close()
{
    try
    {
        m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        m_socket.close();
    }
    catch (...)
    {
    }
}

void Session::check_deadline()
{
    if (m_deadline.expires_at() <= boost::asio::deadline_timer::traits_type::now())
    {
      boost::system::error_code ignored_ec;
      m_socket.close(ignored_ec);
      m_deadline.expires_at(boost::posix_time::pos_infin);
    }

    // Put the actor back to sleep.
    m_deadline.async_wait(boost::lambda::bind(&Session::check_deadline, this));
}
