/*
  Copyright 2019 Tenable, Inc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                *

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
#ifndef SESSION_HPP
#define SESSION_HPP

#include <string>
#include <boost/asio.hpp>

class WinboxMessage;

/**
 * Base class for Winbox_Session and JSProxySession. Allows the developer to combine PoC
 * into a single project.
 */
class Session
{
public:

    Session(const std::string& p_ip, const std::string& p_port);

    virtual ~Session();

    virtual bool connect();

    virtual void close();

    virtual bool send(const WinboxMessage& p_msg) = 0;

    virtual bool receive(WinboxMessage& p_msg) = 0;

protected:

    virtual void check_deadline();

protected:

    //! the ip address to connet to
    std::string m_ip;

    //! the port to connect to
    std::string m_port;

    //! the IO service associated with our blocking socket
    boost::asio::io_service m_io_service;

    //! the blocking socket we use for communication
    boost::asio::ip::tcp::socket m_socket;

    //! Timer to use with async socket operations
    boost::asio::deadline_timer m_deadline;
};

#endif