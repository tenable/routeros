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
#ifndef MT_CONNECTION_HPP
#define MT_CONNECTION_HPP

#include <string>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include "winbox_message.hpp"

class Logging;

/**
 * Handles an incoming Winbox connection. As written, this object will accepted
 * one unencrypted message, do some analysis, and respond with "insuffucient
 * permissions" (albeit in Winbox format) 
 */
class MT_Connection : public boost::enable_shared_from_this<MT_Connection>
{
public:

    /**
     * \param[in] p_io_context the socket asio context
     * \param[in] p_log the logging mechanism for this program.
     */
    MT_Connection(boost::asio::io_context& p_io_context, Logging& p_log);

    ~MT_Connection();

    //! \return the underlying socket this object is using
    boost::asio::ip::tcp::socket& get_socket();

    /**
     * Used to initialize the connection after the server has created the object
     * 
     * \param[in] p_ip the ip address we are connected to
     * \param[in] p_port the port we are connected to
     * \param[in] p_geo the geo data that maxmind gave us
     */
    void set_info(const std::string& p_ip, boost::uint16_t p_port, const std::string& p_geo);

    /**
     * Parses the first four bytes of the connection to determine how much we should read in.
     */
    void read_header();

private:

    /**
     * Write out response to the socket and close it up.
     */
    void handle_write(const boost::system::error_code& error,
                    std::size_t p_bytes_transferred);
    
    /**
     * Validate the first four bytes look like valid winbox.
     * 
     * \return the size of the chunk advertised in the header
     */
    boost::uint32_t validate_header() const;

    /**
     * Given the chunk length, read it into a string
     * 
     * \param[in] p_msg_size the amount of data to read in
     */
    void read_message(boost::uint32_t p_msg_size);

    /**
     * Convert the data from the wire into a WinboxMessage object and determine if the
     * remote host sent us anything interesting. 
     */
    void analyze_message();

private:

    //! the log to write anything useful to
    Logging& m_log;

    //! the socket we are operating on
    boost::asio::ip::tcp::socket m_socket;

    //! stores the header of the winbox message [total size][chunk size]
    boost::uint8_t m_header_buffer[4];

    //! the unparsed winbox message
    std::string m_binary_msg;

    //! the remote IP address we are talking to
    std::string m_ip;

    //! the remote port we are talking to
    boost::uint16_t m_port;

    //! the geo information provided by the server
    std::string m_geo;

    //! a winbox message to parse the binary message with
    WinboxMessage m_msg;
};

#endif
