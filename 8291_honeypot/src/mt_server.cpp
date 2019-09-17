#include "mt_server.hpp"

#include "logging.hpp"
#include "mt_connection.hpp"

#include <sstream>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

MT_Server::MT_Server(Logging& p_log, GeoLite2PP::DB& p_geoDB,
                     boost::asio::io_context& p_io_context, boost::uint16_t p_port) :
    m_log(p_log),
    m_geoDB(p_geoDB),
    m_io_context(p_io_context),
    m_acceptor(m_io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), p_port)),
    m_port(p_port)
{
    start_accept();
}

MT_Server::~MT_Server()
{
}

void MT_Server::start_accept()
{
    boost::shared_ptr<MT_Connection> new_connection(new MT_Connection(m_io_context, m_log));

    m_acceptor.async_accept(new_connection->get_socket(),
        boost::bind(&MT_Server::handle_accept, this, new_connection,
          boost::asio::placeholders::error));
}

void MT_Server::handle_accept(boost::shared_ptr<MT_Connection> new_connection,
                              const boost::system::error_code& error)
{
    if (!error)
    {

        std::string new_ip(new_connection->get_socket().remote_endpoint().address().to_string());
        boost::uint16_t new_port = new_connection->get_socket().remote_endpoint().port();
        std::string geo("unknown");

        try 
        {
            geo.assign(m_geoDB.get_field(new_ip, "en", GeoLite2PP::VCStr { "country", "names" }));

        }
        catch (const std::exception&)
        {
            // swallow the failure
        }

        new_connection->set_info(new_ip, new_port, geo);
        new_connection->read_header();
    }

    start_accept();
}
