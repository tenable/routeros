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
#ifndef MT_SERVER_HPP
#define MT_SERVER_HPP

#include <boost/cstdint.hpp>
#include <boost/asio.hpp>
#include <GeoLite2PP.hpp>

class MT_Connection;
class Logging;

/**
 * A simple server that listens and spawns MT_Connections when a new connection
 * comes in.
 */
class MT_Server
{
public:

    /**
     * \param[in] p_log the logger will handle where we log to (disk or cout)
     * \param[in] p_geoDB a geodb to look IP addresses up in
     * \param[in] p_io_context the ASIO socket context
     * \param[in] p_port the port to lisent on
     */
    MT_Server(Logging& p_log, GeoLite2PP::DB& p_geoDB, boost::asio::io_context& p_io_context,
                boost::uint16_t p_port);
   
    ~MT_Server();

private:

    //! Begin accepting incoming connections
    void start_accept();

    /**
     * Called when a new connection comes in. Ensures to errors have occurred
     * and then invokes the new connection handling.
     * 
     * \param[in] p_new_connect the connection that just came in
     * \param[in] p_error a thinger describing any error that may have occurred
     */
    void handle_accept(boost::shared_ptr<MT_Connection> p_new_connection,
                       const boost::system::error_code& p_error);

private:

    //! The mechanism for logging to file or screen
    Logging& m_log;

    //! The geodb to look up IP addresses in
    GeoLite2PP::DB& m_geoDB;

    //! Socket io context from asio
    boost::asio::io_context& m_io_context;

    //! Server acceptor 
    boost::asio::ip::tcp::acceptor m_acceptor;

    //! the port to listen on
    boost::uint16_t m_port;
};

#endif
