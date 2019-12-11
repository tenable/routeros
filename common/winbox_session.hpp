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
#ifndef WINBOX_SESSION_HPP
#define WINBOX_SESSION_HPP

#include <string>

#include "session.hpp"

class WinboxMessage;

/*!
 * \brief An object for managing Winbox (port 8291) connections.
 *
 * This object represents the RouterOS nv::Message. It can parse in a message in
 * JSON format (webfig) or in the binary format (webfig and winbox). It can
 * also serialize the message into the binary format as well as the JSON format
 * (although the JSON version is not perfect).
 */
class Winbox_Session : public Session
{

public:
    Winbox_Session(const std::string& p_ip, const std::string& p_port);
    virtual ~Winbox_Session();

    bool login(const std::string& p_username, const std::string& p_password, boost::uint32_t& p_session_id);

    virtual bool send(const WinboxMessage& p_msg);
    virtual bool receive(WinboxMessage& p_msg);

    /**
     * Using the mproxy 2,2 endpoint, request a file to read
     */
    bool m2_mproxy_get_file(const std::string& p_file, std::string& p_result);

    /**
     * Using the mproxy old(?) protocol, request a file to read
     */
    bool old_mproxy_get_file(const std::string& p_file, std::string& p_result);
};

#endif
