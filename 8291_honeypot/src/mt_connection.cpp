#include "mt_connection.hpp"

#include <iostream>
#include <GeoLite2PP.hpp>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/lambda.hpp>

#include "logging.hpp"
#include "list.hpp"
#include "user_dat.hpp"

namespace
{
    bool send_message(WinboxMessage& p_msg, boost::asio::ip::tcp::socket& p_socket)
    {
        std::string serialized(p_msg.serialize_to_binary());

        // each message starts with M2 (message format 2) identifier
        std::string message("M2");
        message.append(serialized.data(), serialized.size());

        if (message.length() > 0xffff)
        {
            std::cerr << "Winbox message oversized" << std::endl;
            return false;
        }

        boost::uint8_t msg_size[] =
        {
            static_cast<boost::uint8_t>(message.length() >> 8),     // 0: upper byte
            static_cast<boost::uint8_t>(message.length() & 0xff)    // 1: lower byte
        };

        boost::asio::streambuf request;
        std::ostream request_stream(&request);

        if (message.length() < 0xfe)
        {
            request_stream << static_cast<boost::uint8_t>(msg_size[1] + 2);
            request_stream << '\x01';
            request_stream << msg_size[0] << msg_size[1];
            request_stream << message;
        }
        else
        {
            request_stream << '\xff' << '\x01';
            request_stream << msg_size[0] << msg_size[1];
            request_stream << message.substr(0, 0xfd);              // 0xff-2, because we write 2 bytes above
            for(size_t i = 0xfd; i < message.length(); i+=0xff)
            {
                boost::uint8_t remain;
                if (message.length() - i > 0xff) remain = 0xff;
                else remain = message.length() - i;
                request_stream << remain << '\xff';
                request_stream << message.substr(i, 0xff);   
            }
        }

        try
        {
            boost::asio::write(p_socket, request);
        }
        catch(const std::exception&)
        {
            return false;
        }

        return true;
    }

    void send_error(WinboxMessage& p_msg, boost::asio::ip::tcp::socket& p_socket)
    {
        // respond with an error message and exit
        // {uff0003:2,uff0004:2,uff0006:1,uff0008:16646153,Uff0001:[],Uff0002:[2,2]}
        WinboxMessage error_reply;
        error_reply.add_u32_array(0xff0002, p_msg.get_u32_array(0xff0001)); // from
        error_reply.add_u32_array(0xff0001, p_msg.get_u32_array(0xff0002)); // to
        error_reply.add_u32(0xff0008, 16646153);
        error_reply.add_u32(0xff0006, p_msg.get_u32(0xff0006));

        send_message(error_reply, p_socket);
    }
}

MT_Connection::MT_Connection(boost::asio::io_context& p_io_context, Logging& p_log) :
    m_log(p_log),
    m_io_service(p_io_context),
    m_socket(m_io_service),
    m_deadline(m_io_service),
    m_header_buffer(),
    m_binary_msg(),
    m_ip(),
    m_port(0),
    m_geo(),
    m_msg(),
    m_state(k_none)
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

void MT_Connection::read_header()
{
    // store the remote ip and port for later use
    m_ip.assign(m_socket.remote_endpoint().address().to_string());
    m_port = m_socket.remote_endpoint().port();

    while (m_state != k_close)
    {
        // set a timer for the first four bytes to come in
        boost::system::error_code ec = boost::asio::error::would_block;
        m_deadline.expires_from_now(boost::posix_time::seconds(2));

        // read in the first four bytes
        boost::asio::async_read(m_socket, boost::asio::buffer(m_header_buffer, 4), boost::asio::transfer_exactly(4), boost::lambda::var(ec) = boost::lambda::_1);
        do
        {
            m_io_service.run_one();
        }
        while (ec == boost::asio::error::would_block);

        if (ec)
        {
            // data didn't come! Do something else?
            return;
        }

        // validate the first four bytes are a valid header. The header can have a variety of flavors.
        boost::uint32_t msg_size = validate_header();
        if (msg_size != 0)
        {
            read_message(msg_size);
        }
    }
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
                if (!m_msg.parse_binary(m_binary_msg))
                {
                    m_log.log(logging::k_error, m_ip, m_port, "Received a non-winbox request");
                    return;
                }
                handle_request();
            }
        });
}

void MT_Connection::do_mproxy_file_request()
{
    boost::uint32_t cmd = m_msg.get_u32(0x00ff0007);
    if (cmd == 7) // open for reading no-auth
    {
        WinboxMessage open_response;

        // find the path the user wants to read.
        std::string path(m_msg.get_string(1));
        m_log.log(logging::k_info, m_ip, m_port, "Request to open: " + path);

        // handle different files differently
        if (path.find("user.dat") != std::string::npos)
        {
            m_log.log(logging::k_exciting, m_ip, m_port, "CVE-2018-14847");
            
            // Respond with the sizeof our user.dat file
            open_response.add_u32(2, 302); // sizeof user.dat
            m_state = k_user_dat_open;
        }
        else if (path == "list")
        {
            // Respond with the sizeof our list file
            open_response.add_u32(2, 1798);
            m_state = k_list_open;
        }
        else
        {
            send_error(m_msg, m_socket);
            return;
        }

        // {u2:188,ufe0001:1,uff0003:2,uff0006:1,Uff0001:[],Uff0002:[2,2]}
        open_response.add_u32(0xfe0001, 1); // session id
        if (m_msg.get_u32(0xff0003))
        {
            open_response.add_u32(0xff0003, m_msg.get_u32(0xff0003)); // seq
        }
        std::vector<boost::uint32_t> to;
        open_response.add_u32_array(0xff0002, m_msg.get_u32_array(0xff0002)); // from
        open_response.add_u32_array(0xff0001, to); // to
        open_response.add_u32(0xff0006, m_msg.get_u32(0xff0006));
        send_message(open_response, m_socket);
    }
    else if (cmd == 4) // read file
    {
        m_log.log(logging::k_info, m_ip, m_port, "Request for file contents");

        WinboxMessage file_contents;

        switch (m_state)
        {
            case k_user_dat_open:
                file_contents.add_raw(3, std::string((const char*)&file::user_dat[0], 302));
                break;
            case k_list_open:
                file_contents.add_raw(3, std::string((const char*)&file::list[0], 1798));
                break;
            default:
                send_error(m_msg, m_socket);
                m_state = k_close;
                return;
        }

        m_state = k_none;
        file_contents.add_u32(0xfe0001, 1); // session id
        if (m_msg.get_u32(0xff0003))
        {
            file_contents.add_u32(0xff0003, m_msg.get_u32(0xff0003)); // seq
        }
        std::vector<boost::uint32_t> to;
        file_contents.add_u32_array(0xff0002, m_msg.get_u32_array(0xff0002)); // from
        file_contents.add_u32_array(0xff0001, to); // to
        file_contents.add_u32(0xff0006, m_msg.get_u32(0xff0006));
        send_message(file_contents, m_socket);
    }
    else if (cmd == 5) // cancel
    {
        // {uff0003:2,uff0006:2,Uff0001:[],Uff0002:[2,2]}
        m_state = k_none;
        WinboxMessage cancel;
        cancel.add_u32(0xfe0001, 1); // session id
        if (m_msg.get_u32(0xff0003))
        {
            cancel.add_u32(0xff0003, m_msg.get_u32(0xff0003)); // seq
        }
        std::vector<boost::uint32_t> to;
        cancel.add_u32_array(0xff0002, m_msg.get_u32_array(0xff0002)); // from
        cancel.add_u32_array(0xff0001, to); // to
        cancel.add_u32(0xff0006, m_msg.get_u32(0xff0006));
        send_message(cancel, m_socket);
    }
}

void MT_Connection::do_login_request()
{
    boost::uint32_t cmd = m_msg.get_u32(0xff0007);
    if (cmd == 4) // hash request
    {
        m_log.log(logging::k_info, m_ip, m_port, "Login hash request.");

        // {uff0003:2,uff0006:2,r9:[116,142,107,57,251,184,239,238,31,107,46,25,154,50,85,182],Uff0001:[],Uff0002:[13,4]}
        m_state = k_init_login;

        WinboxMessage hash_response;
        hash_response.add_u32(0xff0003, m_msg.get_u32(0xff0003)); // seq
        hash_response.add_u32_array(0xff0002, m_msg.get_u32_array(0xff0001)); // from
        hash_response.add_u32_array(0xff0001, m_msg.get_u32_array(0xff0002)); // to
        hash_response.add_u32(0xff0006, m_msg.get_u32(0xff0003));

        std::string salt;
        for (int i = 0; i < 16; i++)
        {
            salt.push_back(rand() & 0xff);
        }
        hash_response.add_raw(9, salt);
        send_message(hash_response, m_socket);
    }
    else if (cmd == 1) // login
    {
        m_log.log(logging::k_info, m_ip, m_port, "Login request.");

        // literally we don't care what they return to us. 
        // {b13:0,ub:524286,uf:0,u10:4,ufe0001:2,uff0003:2,uff0006:3,s11:'mips',s12:'952-hb',s14:'',s15:'RB952Ui-5ac2nD',s16:'3.11',s17:'RB700',s18:'default',ra:[0,255,70,218,235,152,107,199,180,73,96,178,186,32,1,96,168],Uff0001:[],Uff0002:[13,4]}
        m_state = k_logged_in;

        WinboxMessage success;
        success.add_u32(0xfe0001, 1); // session id
        success.add_u32(0xff0003, m_msg.get_u32(0xff0003)); // seq
        success.add_u32_array(0xff0002, m_msg.get_u32_array(0xff0001)); // from
        success.add_u32_array(0xff0001, m_msg.get_u32_array(0xff0002)); // to
        success.add_u32(0xff0006, m_msg.get_u32(0xff0003));
        success.add_boolean(0x13, false);
        success.add_u32(0xb, 52486);
        success.add_u32(0xf, 0);
        success.add_u32(0x10, 4);
        success.add_string(0x11, "mips");
        success.add_string(0x12, "952-hb");
        success.add_string(0x14, "");
        success.add_string(0x15, "RB952Ui-5ac2nD");
        success.add_string(0x16, "3.11");
        success.add_string(0x17, "RB700");
        success.add_string(0x18, "default");
        send_message(success, m_socket);
    }
}

void MT_Connection::handle_request()
{
    auto sys_to(m_msg.get_u32_array(0xff0001));
    if (sys_to.empty())
    {
        m_log.log(logging::k_error, m_ip, m_port, "Received a message with no system to array.");
        return;
    }

    // log the request
    m_log.log(logging::k_info, m_ip, m_port, m_msg.serialize_to_json());

    if (sys_to.size() == 2 && sys_to[0] == 2 && sys_to[1] == 2) // read file
    {
        do_mproxy_file_request();
        return;
    }
    else if (sys_to.size() == 2 && sys_to[0] == 13 && sys_to[1] == 4) // login
    {
        do_login_request();
        return;
    }
    else if (m_state == k_logged_in)
    {
        // let them send to us forever
        m_log.log(logging::k_info, m_ip, m_port, "Post login request!");
        return;
    }

    m_state = k_close;
    send_error(m_msg, m_socket);
}