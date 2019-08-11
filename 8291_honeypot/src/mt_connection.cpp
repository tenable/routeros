#include "mt_connection.hpp"

#include <iostream>
#include <GeoLite2PP.hpp>

#include "logging.hpp"

MT_Connection::MT_Connection(boost::asio::io_context& p_io_context, Logging& p_log) :
    m_log(p_log),
    m_socket(p_io_context),
    m_header_buffer(),
    m_binary_msg(),
    m_ip(),
    m_port(0),
    m_geo(),
    m_msg()
{
}

MT_Connection::~MT_Connection()
{
    if (!m_socket.remote_endpoint().address().to_string().empty())
    {
        std::stringstream log_close;
        log_close << "Closing connection: " << m_ip << ":" << m_port;
        m_log.log(logging::k_info, log_close.str());
    }
}

boost::asio::ip::tcp::socket& MT_Connection::get_socket()
{
    return m_socket;
}

void MT_Connection::set_info(const std::string& p_ip, boost::uint16_t p_port, const std::string& p_geo)
{
    m_ip.assign(p_ip);
    m_port = p_port;
    m_geo.assign(p_geo);

    m_log.log(logging::k_info, m_ip, p_port, "New connection from " + m_geo);
}

void MT_Connection::read_header()
{
    m_ip.assign(m_socket.remote_endpoint().address().to_string());
    m_port = m_socket.remote_endpoint().port();

    auto self(shared_from_this());
    boost::asio::async_read(m_socket, 
        boost::asio::buffer(m_header_buffer, 4),
        [this, self](boost::system::error_code ec, std::size_t)
        {
            if (!ec)
            {
                boost::uint32_t msg_size = validate_header();
                if (msg_size != 0)
                {
                    read_message(msg_size);
                }
            }
        });
}

boost::uint32_t MT_Connection::validate_header() const
{
    boost::uint8_t short_length = m_header_buffer[0];
    boost::uint16_t long_length = ntohs(*reinterpret_cast<const boost::uint16_t*>(&m_header_buffer[2]));

    if (short_length == 0xff)
    {
        return long_length;
    }

    if ((short_length - 2) != long_length)
    {
        return 0;
    }

    return long_length;
}

void MT_Connection::read_message(boost::uint32_t p_msg_size)
{
    m_binary_msg.clear();
    m_binary_msg.resize(p_msg_size);

    auto self(shared_from_this());
    boost::asio::async_read(m_socket, 
        boost::asio::buffer(&m_binary_msg[0], p_msg_size),
        [this, self](boost::system::error_code ec, std::size_t)
        {
            if (!ec)
            {
                m_msg.reset();
                m_msg.parse_binary(m_binary_msg);
                analyze_message();
            }
        });
}

void MT_Connection::analyze_message()
{

    auto sys_to(m_msg.get_u32_array(0x00ff0001));
    if (sys_to.empty())
    {
        m_log.log(logging::k_error, m_ip, m_port, "Received a message with no system to array.");
        return;
    }

    if (sys_to.size() == 2)
    {
        if (sys_to[0] == 2 && sys_to[1] == 2) // read file
        {
            // open for reading no-auth
            if (m_msg.get_u32(0x00ff0007) == 7)
            {
                // CVE-2018-14847 vector. Check out the file path.
                std::string path(m_msg.get_string(1));
                if (path.find("..") != std::string::npos)
                {
                    m_log.log(logging::k_exciting, m_ip, m_port, "CVE-2018-14847 attempt for: " + path);
                }
                else if (!path.empty())
                {
                    m_log.log(logging::k_info, m_ip, m_port, "Request to open: " + path);
                }
            }
        }
        else if (sys_to[0] == 13 && sys_to[0] == 4) // login
        {
            if (m_msg.get_u32(0x00ff0007) == 7)
            {
                m_log.log(logging::k_info, m_ip, m_port, "Initiated login sequence");
            }
        }
    }

    m_log.log(logging::k_info, m_ip, m_port, m_msg.serialize_to_json());

    //respond with an error message and exit
    // {uff0003:2,uff0004:2,uff0006:1,uff0008:16646153,Uff0001:[],Uff0002:[2,2]}
    WinboxMessage error_reply;
    error_reply.add_u32_array(0xff0002, sys_to); // from
    error_reply.add_u32_array(0xff0001, m_msg.get_u32_array(0xff0002)); // to
    error_reply.add_u32(0xff0008, 16646153);
    error_reply.add_u32(0xff0006, m_msg.get_u32(0xff0006));

    // this part was copy/pastaed but... its fine.
    std::string serialized(error_reply.serialize_to_binary());

    // each message starts with M2 (message format 2) identifier
    std::string message("M2");
    message.append(serialized.data(), serialized.size());

    std::string length;
    length.push_back(message.size());

    boost::asio::streambuf request;
    std::ostream request_stream(&request);

    length[0] += 2;

    request_stream << length;
    request_stream << '\x01';
    request_stream << '\x00';

    length[0] -= 2;
    request_stream << length;
    request_stream << message;

    boost::asio::write(m_socket, request);
}