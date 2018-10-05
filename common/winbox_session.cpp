#include "winbox_session.hpp"

#include "winbox_message.hpp"
#include "md5.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include <boost/regex.hpp>
#include <boost/lexical_cast.hpp>

Winbox_Session::Winbox_Session(const std::string& p_ip, const std::string& p_port) :
    m_ip(p_ip),
    m_port(p_port),
    m_io_service(),
    m_socket(m_io_service)
{
}

Winbox_Session::~Winbox_Session()
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

bool Winbox_Session::connect()
{
    try
    {
        boost::asio::ip::tcp::resolver resolver(m_io_service);
        boost::asio::connect(m_socket, resolver.resolve({m_ip.c_str(), m_port.c_str()}));
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return false;
    }
    return true;
}

bool Winbox_Session::login(const std::string& p_username, const std::string& p_password, boost::uint32_t& p_session_id)
{
    WinboxMessage msg;

    if (p_session_id == 0)
    {
        msg.set_to(2, 2);
        msg.set_command(7);
        msg.set_request_id(1);
        msg.set_reply_expected(true);
        msg.add_string(1, "list");
        send(msg);

        msg.reset();
        if (!receive(msg) || msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return false;
        }

        p_session_id = msg.get_session_id();
    }

    // request the challenge
    msg.reset();
    msg.set_to(13, 4);
    msg.set_command(4);
    msg.set_request_id(2);
    msg.set_session_id(p_session_id);
    msg.set_reply_expected(true);
    send(msg);

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
    send(msg);

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

    return true;
}

bool Winbox_Session::send(const WinboxMessage& p_msg)
{
    std::string serialized(p_msg.serialize_to_binary());

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
    return true;
}

bool Winbox_Session::receive(WinboxMessage& p_msg)
{
    // read in the the header
    boost::asio::streambuf response;
    boost::asio::read(m_socket, response, boost::asio::transfer_exactly(4));
    std::string header;
    header.assign(std::istreambuf_iterator<char>(&response), std::istreambuf_iterator<char>());
    response.consume(4);

    // parse the header
    boost::uint32_t to_read = parse_header(header);
    if (to_read == 0)
    {
        std::cerr << "Failed header parsing" << std::endl;
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
            std::cerr << "Padding error." << std::endl;
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

boost::uint32_t Winbox_Session::parse_header(const std::string& p_header)
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
