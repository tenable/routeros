/*
  Copyright 2018-2019 Tenable, Inc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                *

  Redistribution and use in source and binary forms, with or without modification,
  are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice, this
     list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.

  3. Neither the name of the copyright holder nor the names of its contributors
     may be used to endorse or promote products derived from this software
     without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef JSPROXY_SESSION_HPP
#define JSPROXY_SESSION_HPP

#include <string>
#include <boost/asio.hpp>
#include <boost/cstdint.hpp>

#include "rc4.hpp"
#include "session.hpp"

class WinboxMessage;

/*!
 * \brief Implements the RouterOS "/jsproxy" HTTP end point.
 *
 * This implementation works for versions prior to 6.43 (they switched to a new
 * key derivation mechanism). Key derivation is based on MS-CHAPv2 and data is
 * encrypted with RC4. The protocol implementation (Message v2) is implemented
 * outside of this object.
 *
 * The name "jsproxy" is interesting in that the winbox port (8291)
 * is occupied by a binary called "mproxy".
 *
 * Sockets are blocking so some funniness can come of that.
 */
class JSProxySession : public Session
{
public:

    /*!
     * Construct a new JS Proxy Session object.
     *
     * \param[in] p_ip the IPv4 address to connect to
     * \param[in] p_port the port to connect to
     */
    JSProxySession(const std::string& p_ip, const std::string& p_port);

    /*!
     * Deconstructor attempts to close the socket if it hasn't been already
     */
    virtual ~JSProxySession();

    /*!
     * Handles the challenge/response negotiation with the server. This
     * implementation only handles MS-CHAPv2 used in versions before 6.43. It
     * does not attempt to handle the new curve based crypto at all.
     *
     * \param[in] p_username the username to log in as
     * \param[in] p_password the password to use for log in
     * \param[in] p_skipLogin skip the final stage of the curve25519 login process.
     */
    bool negotiateEncryption(const std::string& p_username, const std::string& p_password, bool p_skipLogin=false);


    virtual bool send(const WinboxMessage& p_msg);

    virtual bool receive(WinboxMessage& p_msg);

    /*!
     * Sends an encrypted message from Winbox format
     *
     * \param[in] p_message the message to send
     * \param[in] p_binaryFormat indicates is the message is binary (not json)
     * 
     * \return false on error and true otherwise
     */
    bool sendEncrypted(const WinboxMessage& p_message, bool p_binaryFormat);

    /*!
     * Sends an encrypted message from string format
     *
     * \param[in] p_message the message to send
     * \param[in] p_binaryFormat indicates is the message is binary (not json)
     * 
     * \return false on error and true otherwise
     */
    bool sendEncrypted(const std::string& p_message, bool p_binaryFormat);

    /*!
     * Receives a message. Depending on the version the server may send us
     * binary or JSON, but WinboxMessage should handle this agnostically.
     *
     * \param[in,out] p_message the received message
     * \return true if the function was successful and false otherwise.
     */
    bool recvEncrypted(WinboxMessage& p_message);

    /*!
     * Reads a file from the remote filesystem.
     *
     * \param[in] p_fileName the file to read
     * \param[in,out] p_response the contents of the file
     * \return true if successful and false otherwise
     */
    bool getFile(const std::string& p_fileName, std::string& p_response);

    /*!
     * Upload a file using HTTP PUT.
     *
     * \param[in] p_fileName the name we'll upload the file as
     * \param[in] p_content the contents of the file to upload.
     * \return true if successful and false otherwise.
     */
    bool putFile(const std::string& p_fileName, const std::string& p_content);

    /*!
     * Upload a file using jsproxy/upload
     *
     * \param[in] p_fileName the name we'll upload the file as
     * \param[in] p_content the contents of the file
     * \return true if successful and false otherwise
     */
    bool uploadFile(const std::string& p_fileName, const std::string& p_content);

private:

    /**
     * ROS 6.43+ use a public/private Curve25519 key negotiation. This will negotiate the encryption
     * layer and login the user.
     *
     * \param[in] p_username the user to login as
     * \param[in] p_password the password to use for login
     * \param[in] p_skipLogin skip the final stage of the curve25519 login process.
     *
     * \return true on success and false otherwise
     */
    bool doPublicKey(const std::string& p_username, const std::string& p_password, bool p_skipLogin=false);

    /**
     * ROS 6.0 - 6.42.whatever uses MSCHAPv2 to negotiate the session key. The username and password
     * are mixed into the keying material so ROS treats proper encryption/decryption as good login.
     *
     * \param[in] p_username the user to login as
     * \param[in] p_password the password to use for login
     *
     * \return true on success and false otherwise
     */
    bool doMSCHAPv2(const std::string& p_serverResponse, const std::string& p_username, const std::string& p_password);

    /**
     * Generates the MSCHAPv2 master key.
     */
    void generateMasterKey(const std::string& p_masterKey, const std::string& p_response);

    /**
     * Uses the generated master key to seed the m_rx and m_tx RC4 engines
     */
    void seedRC4(const std::string& p_masterKey, bool p_client);

    /**
     * Frames a given message into the proper [4 id] [4 seq] [payload] format. It will also tweak
     * the message depending if the message is json or binary. Finally, this function can encrypt the
     * payload as well.
     */
    void create_message(std::string& p_message, const std::string& p_payload, bool p_binaryFormat, bool p_encrypt);
    
    /*!
     * Sends a message over HTTP.
     *
     * \param[in] p_message the message to send
     * \param[in] p_binaryFormat indicates is the message is binary (not json)
     *
     * \return true if successful and false otherwise
     */
    bool sendMessage(const std::string& p_message, bool p_binaryFormat);

    /*!
     * Receives an HTTP message. No encryption involved at this point
     *
     * \param[in,out] p_message the message we just read in
     * \param[in,out] p_binaryFormat indicates if the message used "msg" or json.
     * 
     * \return true if successful and false otherwise
     */
    bool recvMessage(std::string& p_message, bool& p_binaryFormat);

private:

    //! the session ID that was assigned to this session
    std::string m_id;

    //! the current amount of data we have transmitted
    boost::uint32_t m_sequence;

    //! the RC4 state for receiving
    RC4 m_rx;

    //! the RC4 state for transmission
    RC4 m_tx;

    //! Our curve25519 public key
    std::array<boost::uint8_t, 32> m_pub_key;

    //! Our curve25519 private key
    std::array<boost::uint8_t, 32> m_priv_key;
};

#endif
