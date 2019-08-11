#include "jsproxy_session.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include <arpa/inet.h>
#include <boost/regex.hpp>
#include <boost/lexical_cast.hpp>

#include "md4.hpp"
#include "des.hpp"
#include "sha1.hpp"
#include "winbox_message.hpp"

namespace
{
    // see https://tools.ietf.org/html/rfc3079
    const std::string s_lchallenge("\x21\x40\x23\x24\x25\x5E\x26\x2A\x28\x29\x5F\x2B\x3A\x33\x7C\x7E");
    const std::string s_padding("        ");

    /*!
     * Converts a string into a URL encoded string. Note that I shamelessly
     * stole this from stack overflow (with some modifications):
     * 
     * https://stackoverflow.com/questions/154536/encode-decode-urls-in-c
     *
     * \param[in] p_value the string to conver
     * \return the url encoded string
     */
    std::string url_encode(const std::string& p_value)
    {
        std::ostringstream escaped;
        escaped.fill('0');
        escaped << std::hex;

        for (std::string::const_iterator i = p_value.begin(), n = p_value.end(); i != n; ++i)
        {
            std::string::value_type c = (*i);

            // Keep alphanumeric and other accepted characters intact
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            {
                escaped << c;
                continue;
            }

            // Any other characters are percent-encoded
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char) c);
            escaped << std::nouppercase;
        }

        return escaped.str();
    }

    /*!
     * Converts the code point to an 8 bit value
     *
     * \param[in] p_seq the data to convert
     * \param[in,out] p_index the current index in p_seq
     * \return the converted value
     */
    boost::uint8_t codePointAt(const std::string& p_seq, std::size_t& p_index)
    {
        char c1 = p_seq[p_index];
        if (c1 & 0x80)
        {
            if ((c1 & 0xf0) != 0xc0)
            {
                throw std::runtime_error("Unhandled unicode size");
            }
            if ((p_index + 1) >= p_seq.length())
            {
                throw std::runtime_error("Not enough data in the string");
            }
            p_index++;

            char high = c1 & 0x03;
            high = high << 6;

            char low = p_seq[p_index++] & 0x3f;
            return (high | low);
        }
        p_index++;
        return c1;
    }

    /*!
     * Converts a string of bytes into a string of code points
     *
     * \param[in] p_seq the string to convert
     * \return the converted string
     */
    std::string fromCharCode(const std::string& p_seq)
    {
        std::string retval;

        for (std::size_t i = 0; i < p_seq.size(); i++)
        {
            char c = p_seq[i];
            if (c == 0)
            {
                retval.push_back('\xc4');
                retval.push_back('\x80');
            }
            else if ((c & 0x80) == 0)
            {
                retval.push_back(c);
            }
            else
            {
                char c1_high = ((c & 0xc0) >> 6) & 0xff;
                c1_high = c1_high | 0xc0;
                retval.push_back(c1_high);

                char c1_low = (c & 0x3f) & 0xff;
                c1_low = c1_low | 0x80;
                retval.push_back(c1_low);
            }
        }
        return retval;
    }

    /*!
     * Generates the unencrypted challenge response. Will later be encrypted.
     *
     * \param[in] p_rchallenge the challenge the server sent
     * \param[in] p_username the username of the user logging in
     * \return the unencrypted challenge response
     */
    std::string createChallengeHash(const std::string p_rchallenge, const std::string& p_username)
    {
        std::string challenge(s_lchallenge);
        challenge.append(p_rchallenge);
        challenge.append(p_username);
        unsigned char result[20] = { 0 };
        sha1::calc(challenge.data(), challenge.size(), result);
        std::string challengeHash((char*)result, 20);
        challengeHash.resize(8);
        return challengeHash;
    }

    /*!
     * Converts the password to code points and insert a null after every
     * point. I'm really not sure why this is done.
     *
     * \param[in] p_pass the user's password
     * \return the password converted to the weird format
     */
    std::string weirdPasswordThing(const std::string& p_pass)
    {
        std::string retval;
        for (std::size_t i = 0; i < p_pass.size(); )
        {
            retval.push_back(codePointAt(p_pass, i));
            retval.push_back('\x00');
        }
        return retval;
    }

    /*!
     * Generates a DES key based on the hash value passed in
     *
     * \param[in] p_hash the md4(md4(password)) hash
     * \param[in] j the value used to select the hash index
     * \return a key to be used in DES encryption
     */
    std::string makeDESKey(const std::string& p_hash, std::size_t j)
    {
        std::string retVal;
        for(std::size_t i = j; i < (j + 56); i += 7)
        {
            uint16_t w = p_hash[i >> 3];
            w <<= 8;
            w |= (p_hash[(i >> 3) + 1] & 0xff);
            retVal.push_back((w >> (8 - (i & 7))) & 0xfe);
        }
        return retVal;
    }

    /*!
     * Generates the three part challenge response. Each 3rd is encrypted with
     * a different DES key (that is based on the hashhash of the password).
     *
     * \param[in] p_pwdHash the md4(md4(password)) hash
     * \param[in,out] p_challengeHash the computed response hash (sha1 of username and both challenges)
     * \return the challenge response
     */
    std::string createResponse(const std::string& p_pwdHash, const std::string& p_challengeHash)
    {
        std::string paddedHash(p_pwdHash);
        paddedHash.resize(24, 0);
        std::string response;
        std::string encrypted;
        std::string desKey1(makeDESKey(paddedHash, 0));
        DES::des(p_challengeHash, desKey1, encrypted);
        response.append(encrypted);
        encrypted.clear();
        std::string desKey2(makeDESKey(paddedHash, 56));
        DES::des(p_challengeHash, desKey2, encrypted);
        response.append(encrypted);
        encrypted.clear();
        std::string desKey3(makeDESKey(paddedHash, 112));
        DES::des(p_challengeHash, desKey3, encrypted);
        response.append(encrypted);
        return response;
    }

    /*!
     * Generates the message that contains the challenge response.
     *
     * \param[in,out] p_response the challenge response
     * \param[in] p_id the session id
     * \param[in] p_rchallenge the initial challenge
     * \param[in] p_username the user logging in
     * \return the challenge response
     */
    std::string generateMsgResponse(const std::string& p_response, const std::string& p_id,
                                    const std::string& p_rchallenge, const std::string& p_username)
    {
        std::string msg;
        msg.append("\x00\x00", 2);
        msg.append(s_lchallenge);
        msg.append("\x00\x00\x00\x00\x00\x00\x00\x00", 8);
        msg.append(p_response);

        std::string final = fromCharCode(p_id);
        std::string zero_string("\x00\x00\x00\x00", 4); // seq number
        final.append(fromCharCode(zero_string));
        final.append(fromCharCode(p_rchallenge));
        final.append(fromCharCode(msg));
        final.append(p_username);
        return final;
    }
}

JSProxySession::JSProxySession(const std::string& p_ip, const std::string& p_port) :
    Session(p_ip, p_port),
    m_id(),
    m_sequence(1),
    m_io_service(),
    m_socket(m_io_service),
    m_rx(),
    m_tx()
{
}

JSProxySession::~JSProxySession()
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

bool JSProxySession::connect()
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

bool JSProxySession::negotiateEncryption(const std::string& p_username, const std::string& p_password)
{
    // send a POST request to the device in order to obtain the challenge
    std::string message;
    sendMessage(message);
 
    if (!recvMessage(message))
    {
        std::cerr << "Failed to receive the challenge" << std::endl;
        return false;
    }

    // First four bytes are ID
    std::size_t index = 0;
    for (std::size_t i = 0; i < 4; i++)
    {
        try
        {
            int codePoint = codePointAt(message, index) & 0xff;
            m_id.push_back(codePoint);
        }
        catch(const std::exception&)
        {
            return false;
        }
    }

    for (std::size_t i = 0; i < 4; i++)
    {
        try
        {
            codePointAt(message, index);
        }
        catch(const std::exception&)
        {
            return false;
        }
    }

    // extract the 16 byte challenge
    std::string rchallenge;
    for ( ; index < message.length(); )
    {
        try
        {
            int codePoint = codePointAt(message, index) & 0xff;
            rchallenge.push_back(codePoint);
        }
        catch (const std::exception&)
        {
            return false;
        }
    }

    if (rchallenge.size() != 16)
    {
        std::cerr << "Invalid rchallenge size." << std::endl;
        return false;
    }

    // create the challenge hash (sha1 of client challenge, username, and server challenge)
    std::string challengeHash(createChallengeHash(rchallenge, p_username));

    // generate the password hashes
    std::string pwdHash;
    try
    {
        pwdHash.assign(MD4::md4(weirdPasswordThing(p_password)));
    }
    catch(const std::exception&)
    {
       return false;
    }

    std::string pwdHashHash(MD4::md4(pwdHash));

    // generate the challenge response
    std::string response(createResponse(pwdHash, challengeHash));

    // create the master key
    generateMasterKey(pwdHashHash, response);

    // generate the final response message
    std::string final(generateMsgResponse(response, m_id, rchallenge, p_username));

    // send the challenge response
    sendMessage(final);

    WinboxMessage msg;
    if (!recvEncrypted(msg) || msg.get_u32_array(0xff0001).empty())
    {
        std::cerr << "Failed to receive the challenge" << std::endl;
        return false;
    }

    return true;
}

void JSProxySession::generateMasterKey(const std::string& p_pwdHashHash, const std::string& p_response)
{
    std::string masterKey(p_pwdHashHash);
    masterKey.append(p_response);
    masterKey.append("This is the MPPE Master Key");

    unsigned char sharesult[20] = { 0 };
    sha1::calc(masterKey.data(), masterKey.size(), sharesult);
    masterKey.assign((char*)sharesult, 16);

    // generate the send and receive RC4 contexts
    for (int i = 0; i < 40; ++i)
    {
        masterKey.push_back(0);
    }

    std::string server_key(masterKey);
    server_key.append("On the client side, this is the receive key; on the server side, it is the send key.");
    for (int i = 0; i < 40; ++i)
    {
        server_key.push_back(0xf2);
    }
    unsigned char serversha[20] = { 0 };
    sha1::calc(server_key.data(), server_key.size(), serversha);
    server_key.assign((char*)serversha, 16);
    m_rx.setKey(server_key);

    std::string client_key(masterKey);
    client_key.append("On the client side, this is the send key; on the server side, it is the receive key.");
    for (int i = 0; i < 40; ++i)
    {
        client_key.push_back(0xf2);
    }
    unsigned char clientsha[20] = { 0 };
    sha1::calc(client_key.data(), client_key.size(), clientsha);
    client_key.assign((char*)clientsha, 16);
    m_tx.setKey(client_key);
}

void JSProxySession::sendMessage(const std::string& p_message)
{
    boost::uint32_t message_length = p_message.size();

    boost::asio::streambuf request;
    std::ostream request_stream(&request);

    request_stream << "POST /jsproxy HTTP/1.1\r\n";
    request_stream << "Host: " << m_ip << ":" << m_port << "\r\n";
    request_stream << "Content-Length: " << message_length << "\r\n";
    request_stream << "Content-Type: text/plain;charset=UTF-8\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: keep-alive\r\n\r\n";
    request_stream << p_message;

    boost::asio::write(m_socket, request);
}

bool JSProxySession::recvMessage(std::string& p_message)
{
    // read until the end of the HTTP header
    boost::asio::streambuf response;
    std::size_t amount_read = 0;
    try
    {
        amount_read = boost::asio::read_until(m_socket, response, "\r\n\r\n");
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return false;
    }

    std::string http_header{boost::asio::buffers_begin(response.data()), 
                            boost::asio::buffers_begin(response.data()) + amount_read };
    std::stringstream headerstream(http_header);
    response.consume(amount_read);

    // extract the content length
    boost::uint32_t length = 0;
    std::string http_response;
    while (std::getline(headerstream, http_response))
    {
        boost::regex content_length{"Content-Length: (\\d+)"};
        boost::smatch what;
        if (boost::regex_search(http_response, what, content_length))
        {
            length = boost::lexical_cast<boost::uint32_t>(what[1]);
        }
    }

    if (length == 0)
    {
        return false;
    }

    if (response.size() <= length)
    {
        length -= response.size();
    }

    boost::asio::read(m_socket, response, boost::asio::transfer_exactly(length));
    p_message.assign(std::istreambuf_iterator<char>(&response), std::istreambuf_iterator<char>());

    if (http_header.find("500 Internal Server Error") != std::string::npos)
    {
        std::cerr << "Server replied with 500." << std::endl;
        return false;
    }
    return true;
}

bool JSProxySession::send(const WinboxMessage& p_msg)
{
    // wrapper around send encrypted
    sendEncrypted(p_msg);
    return true;
}

bool JSProxySession::receive(WinboxMessage& p_msg)
{
    // wrapper around recv encrypted
    return recvEncrypted(p_msg);
}

void JSProxySession::sendEncrypted(const WinboxMessage& p_message)
{
    // create the preamble
    std::string preamble(m_id);
    preamble.resize(8, 0);
    boost::uint32_t reversed = ntohl(m_sequence);
    memcpy(const_cast<char*>(preamble.data()) + 4, &reversed, 4);

    std::string message(p_message.serialize_to_json());
    message.append(s_padding);

    // increment the sequence number for next time
    m_sequence += (message.length());

    // encrypt
    std::string encrypted(m_tx.decrypt(message, 0));

    preamble.append(encrypted);

    // funkify
    std::string final(fromCharCode(preamble));

    sendMessage(final);
}

void JSProxySession::sendEncrypted(const std::string& p_message)
{
    // create the preamble
    std::string preamble(m_id);
    preamble.resize(8, 0);
    boost::uint32_t reversed = ntohl(m_sequence);
    memcpy(const_cast<char*>(preamble.data()) + 4, &reversed, 4);

    std::string message(p_message);
    message.append(s_padding);

    // increment the sequence number for next time
    m_sequence += (message.length());

    // encrypt
    std::string encrypted(m_tx.decrypt(message, 0));

    preamble.append(encrypted);

    // funkify
    std::string final(fromCharCode(preamble));

    sendMessage(final);
}

bool JSProxySession::getFile(const std::string& p_fileName, std::string& p_response)
{
    // create the preamble
    std::string preamble(m_id);
    preamble.resize(8, 0);
    boost::uint32_t reversed = ntohl(m_sequence);
    memcpy(const_cast<char*>(preamble.data()) + 4, &reversed, 4);

    // increment the sequence number for next time
    m_sequence += (p_fileName.length() + s_padding.length());

    // add padding and encrypt
    std::string message(p_fileName);
    message.append(s_padding);
    std::string encrypted(m_tx.decrypt(message, 0));

    // combine all the things
    preamble.append(encrypted);

    // funkify
    std::string final(fromCharCode(preamble));

    // url encode instead of the fromCharCode funkification
    preamble = url_encode(final);

    // send it!
    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "GET /jsproxy/?" << preamble;
    request_stream << " HTTP/1.1\r\n";
    request_stream << "Host: " << m_ip << ":" << m_port << "\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: keep-alive\r\n\r\n";

    boost::asio::write(m_socket, request);

    // grab the response
    return recvMessage(p_response);
}

bool JSProxySession::putFile(const std::string& p_fileName, const std::string& p_content)
{
    // create the preamble
    std::string preamble(m_id);
    preamble.resize(8, 0);
    boost::uint32_t reversed = ntohl(m_sequence);
    memcpy(const_cast<char*>(preamble.data()) + 4, &reversed, 4);

    // increment the sequence number for next time
    m_sequence += (p_fileName.length() + s_padding.length());

    // add padding and encrypt
    std::string message(p_fileName);
    message.append(s_padding);
    std::string encrypted(m_tx.decrypt(message, 0));

    // combine all the things
    preamble.append(encrypted);

    // funkify
    std::string final(fromCharCode(preamble));

    // url encode instead of the fromCharCode funkification
    preamble = url_encode(final);

    boost::uint32_t message_length = p_content.size();

    boost::asio::streambuf request;
    std::ostream request_stream(&request);

    request_stream << "POST /jsproxy/put?";
    request_stream << preamble;
    request_stream << " HTTP/1.1\r\n";
    request_stream << "Host: " << m_ip << ":" << m_port << "\r\n";
    request_stream << "Content-Length: " << message_length << "\r\n";
    request_stream << "Content-Type: text/plain;charset=UTF-8\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: keep-alive\r\n\r\n";
    request_stream << p_content;

    boost::asio::write(m_socket, request);
    return true;
}

bool JSProxySession::uploadFile(const std::string& p_fileName, const std::string& p_content)
{
    // create the preamble
    std::string preamble(m_id);
    preamble.resize(8, 0);
    boost::uint32_t reversed = ntohl(m_sequence);
    memcpy(const_cast<char*>(preamble.data()) + 4, &reversed, 4);

    // increment the sequence number for next time
    m_sequence += s_padding.length();

    // add padding and encrypt
    std::string message(s_padding);
    std::string encrypted(m_tx.decrypt(message, 0));

    // combine all the things
    preamble.append(encrypted);

    // funkify
    std::string final(fromCharCode(preamble));

    // url encode instead of the fromCharCode funkification
    preamble = url_encode(final);

    std::stringstream payload;
    payload << "-----------------------------7e223912c009c\r\n";
    payload << "Content-Disposition: form-data; name=\"file\"; filename=\"" << p_fileName << "\"\r\n";
    payload << "Content-Type: application/octet-stream\r\n\r\n";
    payload << p_content;
    payload << "\r\n\r\n";
    payload << "-----------------------------7e223912c009c--\r\n";

    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "POST /jsproxy/upload?";
    request_stream << preamble;
    request_stream << " HTTP/1.1\r\n";
    request_stream << "Host: " << m_ip << ":" << m_port << "\r\n";
    request_stream << "Content-Type: multipart/form-data; boundary=---------------------------7e223912c009c\r\n";
    request_stream << "Content-Length: " << payload.str().length() << "\r\n\r\n";
    request_stream << payload.str();

    boost::asio::write(m_socket, request);
    return true;
}

bool JSProxySession::recvEncrypted(WinboxMessage& p_message)
{
    std::string message;
    if (!recvMessage(message))
    {
        return false;
    }

    // skip the first 8 bytes [4 bytes id][4 bytes sequence] where sequence is len(payload) + 8
    std::size_t index = 0;
    std::string id;
    for (std::size_t i = 0; i < 4; i++)
    {
        try
        {
            int codePoint = codePointAt(message, index);
            id.push_back(codePoint);
        }
        catch (const std::exception&)
        {
            return false;
        }
    }

    std::string sequence;
    for (std::size_t i = 0; i < 4; i++)
    {
        try
        {
            int codePoint = codePointAt(message, index);
            sequence.push_back(codePoint);
        }
        catch (const std::exception&)
        {
            return false;
        }
    }

    std::string converted;
    for ( ; index < message.length(); )
    {
        try
        {       
            int codePoint = codePointAt(message, index) & 0xff;
            converted.push_back(codePoint);
        }
        catch (const std::exception&)
        {
            return false;
        }
    }

    message.assign(m_rx.decrypt(converted, 0));

    if (!message.empty())
    {
        if (message[0] == '{')
        {
            p_message.parse_json(message);
        }
        else
        {
            p_message.parse_binary(message);
        }
    }

    return true;
}
