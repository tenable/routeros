#include "winbox_session.hpp"

#include "winbox_message.hpp"
#include "md5.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/lambda.hpp>

namespace
{
    /*!
     * Validates the first four bytes of the header. The first byte is the size of this chunk. The
     * second byte indicates if there are more packets in this series. The third and fourth bytes
     * are the total length.
     * 
     * \return 0 if failure and the length we need to read otherwise
     */
    boost::uint32_t parse_header(const std::string& p_header)
    {
        if (p_header.size() != 4)
        {
            return 0;
        }

        boost::uint8_t short_length = p_header[0];
        boost::uint16_t long_length = ntohs(*reinterpret_cast<const boost::uint16_t*>(&p_header[2]));

        if (short_length == 0xff)
        {
            return long_length;
        }

        if ((short_length - 2) != long_length)
        {
            std::cerr <<  std::hex << "Length mismatch. " << (short_length -2) << " != " << long_length << std::endl;
            return 0;
        }

        return long_length;
    }
}

Winbox_Session::Winbox_Session(const std::string& p_ip, const std::string& p_port) :
    Session(p_ip, p_port)

{
}

Winbox_Session::~Winbox_Session()
{
}

bool Winbox_Session::login(const std::string& p_username, const std::string& p_password, boost::uint32_t& p_session_id)
{
    WinboxMessage msg;

    // request the challenge
    msg.set_to(13, 4);
    msg.set_command(4);
    msg.set_request_id(2);
    msg.set_session_id(p_session_id);
    msg.set_reply_expected(true);
    if (!send(msg))
    {
        return false;
    }

    msg.reset();
    if (!receive(msg) || msg.has_error())
    {
        std::cerr << msg.get_error_string() << std::endl;
        return false;
    }

    std::string salt(msg.get_raw(0x9));
    if (salt.size() != 16)
    {
        msg.reset();
        if (!receive(msg) || msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return false;
        }
        salt.assign(msg.get_raw(0x9));
    }

    // generate the challenge response
    std::string one;
    one.push_back(0);

    MD5 md5;
    md5.update(one.data(), one.length());
    md5.update(p_password.data(), p_password.length());
    md5.update(salt.data(), salt.length());
    md5.finalize();

    std::string hashed(md5.getDigest());
    hashed.insert(0, "\x0", 1);

    msg.reset();
    msg.set_to(13, 4);
    msg.set_command(1);
    msg.set_request_id(3);
    msg.set_session_id(p_session_id);
    msg.set_reply_expected(true);
    msg.add_string(1, p_username);
    msg.add_raw(9, salt);
    msg.add_raw(10, hashed);
    if (!send(msg))
    {
        return false;
    }

    msg.reset();
    if (!receive(msg))
    {
        std::cerr << "Error receiving a response." << std::endl;
        return false;
    }

    if (msg.has_error())
    {
        std::cerr << msg.get_error_string() << std::endl;
        return false;
    }

    p_session_id = msg.get_session_id();

    return true;
}

bool Winbox_Session::send(const WinboxMessage& p_msg)
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
        // convert to async with timer
        boost::asio::write(m_socket, request);
    }
    catch(const std::exception&)
    {
        return false;
    }

    return true;
}

bool Winbox_Session::receive(WinboxMessage& p_msg)
{
    boost::system::error_code ec = boost::asio::error::would_block;
    m_deadline.expires_from_now(boost::posix_time::seconds(2));

    // read in the the header
    boost::asio::streambuf response;
    boost::asio::async_read(m_socket, response, boost::asio::transfer_exactly(4), boost::lambda::var(ec) = boost::lambda::_1);
    do
    {
        m_io_service.run_one();
    }
    while (ec == boost::asio::error::would_block);

    if (ec)
    {
        return false;
    }

    std::string header;
    header.assign(std::istreambuf_iterator<char>(&response), std::istreambuf_iterator<char>());
    response.consume(4);

    // parse the header
    boost::uint32_t to_read = parse_header(header);
    if (to_read == 0)
    {
        //std::cerr << "Failed header parsing" << std::endl;
        return false;
    }

    std::string message;
    for (int i = 0; to_read > 0xff; i++)
    {
        boost::uint32_t step = 0xff;
        if (i == 0)
        {
            // in the first iteration we already read in the first 3 bytes
            step = 0x100 - 3;
        }

        boost::asio::read(m_socket, response, boost::asio::transfer_exactly(step));
        message.append(std::istreambuf_iterator<char>(&response), std::istreambuf_iterator<char>());
        response.consume(step);
        to_read -= step;

        // should be two bytes of 0xff here
        std::string step_chars;
        boost::asio::read(m_socket, response, boost::asio::transfer_exactly(2));
        step_chars.assign(std::istreambuf_iterator<char>(&response), std::istreambuf_iterator<char>());
        response.consume(2);

        // ensure pad bytes are there
        if (static_cast<unsigned char>(step_chars[1]) != 0xff)
        {
            //std::cerr << "Padding error." << std::endl;
            return false;
        }
    }

    // read the last bit of data
    boost::asio::read(m_socket, response, boost::asio::transfer_exactly(to_read));
    message.append(std::istreambuf_iterator<char>(&response), std::istreambuf_iterator<char>());
    response.consume(to_read);

    // remove the M2 header and load into a message obj
    message.erase(0, 2);
    p_msg.parse_binary(message);

    return true;
}

bool Winbox_Session::m2_mproxy_get_file(const std::string& p_file, std::string& p_result)
{
    WinboxMessage msg;
    msg.set_to(2, 2);
    msg.set_command(7);
    msg.set_request_id(1);
    msg.set_reply_expected(true);
    msg.add_string(1, p_file);
    if (!send(msg))
    {
        return false;
    }

    msg.reset();
    if (!receive(msg))
    {
        return false;
    }

    if (msg.has_error())
    {
        p_result.assign(msg.get_error_string());
        return false;
    }

    boost::uint32_t sessionID = msg.get_session_id();
    boost::uint16_t file_size = msg.get_u32(2);

    if (file_size == 0)
    {
        // new version will just indicate file size is 0
        return true;
    }

    msg.reset();
    msg.set_to(2, 2);
    msg.set_command(4);
    msg.set_request_id(2);
    msg.set_reply_expected(true);
    msg.set_session_id(sessionID);
    msg.add_u32(2, file_size);
    send(msg);

    msg.reset();
    if (!receive(msg))
    {
        return false;
    }

    if (msg.has_error())
    {
        p_result.assign(msg.get_error_string());
        return false;
    }

    p_result.assign(msg.get_raw(0x03));
    return true;
}

bool Winbox_Session::old_mproxy_get_file(const std::string& p_file, std::string& p_result)
{
    std::string index_file_request(p_file);
    if (index_file_request.size() > 12)
    {
        return false;
    }

    while (index_file_request.size() < 12)
    {
        index_file_request.push_back('\x00');
    }
    index_file_request.append("\x00\x80\x00\x00\x00\x00", 6);

    boost::uint8_t length = index_file_request.length();
    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << length << '\x02' << index_file_request;

    try
    {
        boost::asio::write(m_socket, request);
    }
    catch(const std::exception&)
    {
        return false;
    }

    boost::system::error_code ec = boost::asio::error::would_block;
    m_deadline.expires_from_now(boost::posix_time::seconds(2));

    // read in the the header
    boost::asio::streambuf response;
    boost::asio::async_read(m_socket, response, boost::asio::transfer_exactly(2), boost::lambda::var(ec) = boost::lambda::_1);
    do
    {
        m_io_service.run_one();
    }
    while (ec == boost::asio::error::would_block);

    if (ec)
    {
        return false;
    }

    std::string header;
    header.assign(std::istreambuf_iterator<char>(&response), std::istreambuf_iterator<char>());
    response.consume(2);

    // read in the remainder
    boost::uint32_t to_read = header[0] & 0xff;
    boost::asio::read(m_socket, response, boost::asio::transfer_exactly(to_read));


    p_result.assign(std::istreambuf_iterator<char>(&response), std::istreambuf_iterator<char>());
    response.consume(to_read);

    return true;
}
