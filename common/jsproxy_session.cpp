#include "jsproxy_session.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include <arpa/inet.h>
#include <boost/regex.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/lambda.hpp>

#include "md4.hpp"
#include "des.hpp"
#include "sha1.hpp"
#include "winbox_message.hpp"
#include "curve25519-donna.hpp"

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

    /*!
     * When ROS sends text/plain payloads, then the payload is json encoded with javascript madness. This
     * function will strip away the encoding and seperate the message into its individual parts:
     * [4 bytes id] [4 bytes seq] [n payload]
     *
     * \param[in] p_input the data to shove through the codePointAt logic and pull out the individual parts
     * \param[in,out] p_id the id we extract from p_input (four bytes)
     * \param[in,out] p_seq the seq we extract from p_input (four bytes)
     * \param[in,out] p_payload the payload we extract from p_input (the remaining data)
     */
    bool read_js_encoded_message(const std::string& p_input, std::string& p_id, std::string& p_seq, std::string& p_payload)
    {
        std::size_t index = 0;
        for (std::size_t i = 0; i < 4; i++)
        {
            try
            {
                int codePoint = codePointAt(p_input, index) & 0xff;
                p_id.push_back(codePoint);
            }
            catch(const std::exception&)
            {
                return false;
            }
        }

        // sequence numbers. we don't really care.
        for (std::size_t i = 0; i < 4; i++)
        {
            try
            {
                int codePoint = codePointAt(p_input, index);
                p_seq.push_back(codePoint);
            }
            catch(const std::exception&)
            {
                return false;
            }
        }

        // extract the remainder
        for ( ; index < p_input.length(); )
        {
            try
            {
                int codePoint = codePointAt(p_input, index) & 0xff;
                p_payload.push_back(codePoint);
            }
            catch (const std::exception&)
            {
                return false;
            }
        }

        return true;
    }
}

JSProxySession::JSProxySession(const std::string& p_ip, const std::string& p_port) :
    Session(p_ip, p_port),
    m_id(),
    m_sequence(1),
    m_rx(),
    m_tx(),
    m_pub_key(),
    m_priv_key()
{
    // generate a priv/pub key pair
    srand(time(NULL));
    for (std::size_t i = 0; i < m_priv_key.size(); i++)
    {
        m_priv_key[i] = (rand() % 256);
    }

    // very very oddly, MT's implementation reverses their keys. See:
    // https://github.com/rev22/curve255js/issues/4#issuecomment-513459563
    std::reverse(m_priv_key.begin(), m_priv_key.end());

    static const boost::uint8_t basepoint[32] = {9};
    curve25519_donna(&m_pub_key[0], &m_priv_key[0], basepoint);
}

JSProxySession::~JSProxySession()
{
}

bool JSProxySession::negotiateEncryption(const std::string& p_username, const std::string& p_password, bool p_skipLogin)
{
    // so this is kind of annoying. Depending on the version, RouterOS either wants an empty post or
    // a post containing our public key. My goal for this library is to support backwards compatiblity.
    // as such this is what we'll do:
    // 1. Try an empty post. If that works - awesome!
    // 2. If not, disconnect / reconnect
    // 3. Send a the public key.
    // 4. If that fails then I don't know wtf.

    // send an empty POST request to the device in order to obtain the challenge
    std::string message;
    if (!sendMessage(message, false))
    {
        return false;
    }
 
    bool p_binaryFormat = false;
    if (!recvMessage(message, p_binaryFormat))
    {
        // the empty post didn't work. Try a post with the public key
        close();
        if (!connect())
        {
            return false;
        }
        return doPublicKey(p_username, p_password, p_skipLogin);
    }

    return doMSCHAPv2(message, p_username, p_password);
}

bool JSProxySession::doPublicKey(const std::string& p_username, const std::string& p_password, bool p_skipLogin)
{
    std::string pubkey_msg;

    // first 8 bytes are all set to 0.
    for (std::size_t i = 0; i < 8; i++)
    {
        pubkey_msg.push_back('\x00');
    }

    // remaining 32 bytes are our public key (in reverse order...)
    for (int i = m_pub_key.size(); i > 0; i--)
    {
        pubkey_msg.push_back(m_pub_key[i - 1]);
    }

    // convert into javascript nonsense and send it off
    sendMessage(fromCharCode(pubkey_msg), false);

    // Get their pub key in response
    std::string pub_key_response;
    bool p_binaryFormat = false;
    if (!recvMessage(pub_key_response, p_binaryFormat))
    {
        return false;
    }

    if (pub_key_response.size() < 40)
    {
        return false;
    }

    m_id.clear();
    std::string seq; // don't actually care
    std::string server_pubkey;
    if (!read_js_encoded_message(pub_key_response, m_id, seq, server_pubkey))
    {
        return false;
    }

    if (server_pubkey.size() != 32)
    {
        return false;
    }

    // again, we need to reverse the key
    std::reverse(server_pubkey.begin(), server_pubkey.end());

    // generate the session key
    std::array<boost::uint8_t, 32> session_key = { 0 };
    curve25519_donna(&session_key[0], &m_priv_key[0], reinterpret_cast<const boost::uint8_t*>(&server_pubkey[0]));

    // ...of course we have to reverse the session key too.
    std::reverse(session_key.begin(), session_key.end());

    std::string masterKey(reinterpret_cast<const char*>(&session_key[0]), session_key.size());
    for (int i = 0; i < 40; ++i)
    {
        masterKey.push_back(0);
    }

    seedRC4(masterKey, false);
    seedRC4(masterKey, true);

    // if we want to do some weird stuff (cve-2019-13955) then we have to skip the final
    // stage of login
    if (p_skipLogin)
    {
        return true;
    }

    WinboxMessage win_msg;
    win_msg.add_string(1, p_username);
    win_msg.add_string(3, p_password);
    if (!sendEncrypted(win_msg, true))
    {
        return false;
    }

    win_msg.reset();
    return recvEncrypted(win_msg);
}

bool JSProxySession::doMSCHAPv2(const std::string& p_serverResponse, const std::string& p_username, const std::string& p_password)
{
    m_id.clear();
    std::string seq; // don't actually care
    std::string rchallenge;
    if (!read_js_encoded_message(p_serverResponse, m_id, seq, rchallenge))
    {
        return false;
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
    sendMessage(final, false);

    WinboxMessage msg;
    if (!recvEncrypted(msg) || msg.get_u32_array(0xff0001).empty())
    {
        std::cerr << "Error receiving or decrypting the challenge: " << msg.serialize_to_json() << std::endl;
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

    seedRC4(masterKey, false);
    seedRC4(masterKey, true);
}

void JSProxySession::seedRC4(const std::string& p_masterKey, bool p_client)
{
    std::string key(p_masterKey);
    if (p_client)
    {
        key.append("On the client side, this is the send key; on the server side, it is the receive key.");
    }
    else
    {
        key.append("On the client side, this is the receive key; on the server side, it is the send key.");
    }

    for (int i = 0; i < 40; ++i)
    {
        key.push_back(0xf2);
    }

    unsigned char sha[20] = { 0 };
    sha1::calc(key.data(), key.size(), sha);
    key.assign((char*)sha, 16);

    if (p_client)
    {
        m_tx.setKey(key);
    }
    else 
    {
        m_rx.setKey(key);
    }
}

void JSProxySession::create_message(std::string& p_message, const std::string& p_payload, bool p_binaryFormat, bool p_encrypt)
{
    // create the preamble first: [4 bytes id][4 bytes seq]
    p_message.assign(m_id);
    p_message.resize(8, 0);
    boost::uint32_t reversed = ntohl(m_sequence);
    memcpy(const_cast<char*>(p_message.data()) + 4, &reversed, 4);

    // add the padding to the payload
    std::string payload;
    if (p_binaryFormat)
    {
        payload.assign("M2");
    }
    payload.append(p_payload);
    payload.append(s_padding);

    // increment the sequence number for next time
    m_sequence += payload.size();

    if (p_encrypt)
    {
        p_message.append(m_tx.decrypt(payload, 0));
    }
    else 
    {
        p_message.append(payload);
    }

    if (p_binaryFormat)
    {
        // no need to do anything else
        return;
    }

    std::string final(fromCharCode(p_message));
    p_message.assign(final);
}

bool JSProxySession::sendMessage(const std::string& p_message, bool p_binaryFormat)
{
    boost::uint32_t message_length = p_message.size();

    boost::asio::streambuf request;
    std::ostream request_stream(&request);

    request_stream << "POST /jsproxy HTTP/1.1\r\n";
    request_stream << "Host: " << m_ip << ":" << m_port << "\r\n";
    request_stream << "Content-Length: " << message_length << "\r\n";
    if (p_binaryFormat)
    {
        request_stream << "Content-Type: msg\r\n";
    }
    else
    {
        request_stream << "Content-Type: text/plain;charset=UTF-8\r\n";
    }
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: keep-alive\r\n\r\n";
    request_stream << p_message;

    boost::asio::write(m_socket, request);
    return true;
}

bool JSProxySession::recvMessage(std::string& p_message, bool& p_binaryFormat)
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

    // extract the content length and the content type. The server supports
    // two types: text/plain (json format) and msg (binary format).
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
        else if (http_response.find("Content-Type: msg") == 0)
        {
            p_binaryFormat = true;
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
        return false;
    }
    return true;
}

bool JSProxySession::send(const WinboxMessage& p_msg)
{
    // wrapper around send encrypted
    return sendEncrypted(p_msg, true);
}

bool JSProxySession::receive(WinboxMessage& p_msg)
{
    // wrapper around recv encrypted
    return recvEncrypted(p_msg);
}

bool JSProxySession::sendEncrypted(const WinboxMessage& p_message, bool p_binaryFormat)
{
    std::string outgoing;
    create_message(outgoing, p_binaryFormat ? p_message.serialize_to_binary() : p_message.serialize_to_json(), p_binaryFormat, true);
    return sendMessage(outgoing, p_binaryFormat);
}

bool JSProxySession::sendEncrypted(const std::string& p_message, bool p_binaryFormat)
{
    std::string outgoing;
    create_message(outgoing, p_message, p_binaryFormat, true);
    return sendMessage(outgoing, p_binaryFormat);
}

bool JSProxySession::getFile(const std::string& p_fileName, std::string& p_response)
{
    std::string final;
    create_message(final, p_fileName, false, true);
    std::string file(url_encode(final));

    // send it!
    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "GET /jsproxy/?" << file;
    request_stream << " HTTP/1.1\r\n";
    request_stream << "Host: " << m_ip << ":" << m_port << "\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: keep-alive\r\n\r\n";

    boost::asio::write(m_socket, request);

    // grab the response
    bool p_doesntmatter = false;
    return recvMessage(p_response, p_doesntmatter);
}

bool JSProxySession::putFile(const std::string& p_fileName, const std::string& p_content)
{
    std::string final;
    create_message(final, p_fileName, false, true);
    std::string file(url_encode(final));

    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "POST /jsproxy/put?" << file << " HTTP/1.1\r\n";
    request_stream << "Host: " << m_ip << ":" << m_port << "\r\n";
    request_stream << "Content-Length: " << p_content.size() << "\r\n";
    request_stream << "Content-Type: text/plain;charset=UTF-8\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: keep-alive\r\n\r\n";
    request_stream << p_content;

    boost::asio::write(m_socket, request);
    return true;
}

bool JSProxySession::uploadFile(const std::string& p_fileName, const std::string& p_content)
{
    std::string final;
    create_message(final, p_fileName, false, true);
    std::string file(url_encode(final));

    std::stringstream payload;
    payload << "-----------------------------7e223912c009c\r\n";
    payload << "Content-Disposition: form-data; name=\"file\"; filename=\"" << p_fileName << "\"\r\n";
    payload << "Content-Type: application/octet-stream\r\n\r\n";
    payload << p_content;
    payload << "\r\n\r\n";
    payload << "-----------------------------7e223912c009c--\r\n";

    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "POST /jsproxy/upload?" << file << " HTTP/1.1\r\n";
    request_stream << "Host: " << m_ip << ":" << m_port << "\r\n";
    request_stream << "Content-Type: multipart/form-data; boundary=---------------------------7e223912c009c\r\n";
    request_stream << "Content-Length: " << payload.str().length() << "\r\n\r\n";
    request_stream << payload.str();

    boost::asio::write(m_socket, request);
    return true;
}

bool JSProxySession::recvEncrypted(WinboxMessage& p_message)
{
    bool binaryFormat = false;
    std::string message;
    if (!recvMessage(message, binaryFormat) || message.size() < 16)
    {
        return false;
    }
  
    std::string encrypted;
    if (binaryFormat == false)
    {
        std::string id;
        std::string seq;
        std::string rchallenge;
        if (!read_js_encoded_message(message, id, seq, encrypted))
        {
            return false;
        }
    }
    else
    {
        // lol id and seq say what?
        message.erase(0, 8);
        encrypted.assign(message);
    }

    // decrypted
    std::string decrypted(m_rx.decrypt(encrypted, 0));

    // we expect *AT LEAST* 8 bytes of padding.
    if (decrypted.size() <= 8)
    {
        return false;
    }

    // validate the padding
    std::string padding(decrypted.substr(decrypted.size() - 8));
    if (padding != "        ")
    {
        std::cout << "Bad decrypt! " << padding << std::endl;
        return false;
    }

    // remove the padding
    decrypted.resize(decrypted.size() - 8 );

    // parse to winbox and return
    return (binaryFormat ? p_message.parse_binary(decrypted) : p_message.parse_json(decrypted));
}
