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
#ifndef LOGGING_HPP
#define LOGGING_HPP

#include <string>
#include <fstream>
#include <boost/cstdint.hpp>

namespace logging
{
    // special formatting for the output. descriptions inline
    enum type
    {
        k_info, // [+]
        k_error, // [-]
        k_exciting // [!]
    };
}

/**
 * Handles the logging between stdout and a file. Also handles most special
 * formatting that the author felt was very very necessary.
 */
class Logging
{
public:
    
    //! \param[in] p_logName the name of the log if it goes to file
    explicit Logging(const std::string& p_logName);

    ~Logging();

    /**
     * Logs a general string using the indicated p_type format.
     * 
     * \param[in] p_type the special format thinger
     * \param[in] p_string the string to log
     */
    void log(logging::type p_type, const std::string& p_string);

    /**
     * Logs a string and associates it with an IP address and port.
     * 
     * \param[in] p_type the special format thinger
     * \param[in] p_ip the remote ip this is associated with
     * \param[in] p_port the remote port this is associated with
     * \param[in] p_string the string to log
     */
    void log(logging::type p_type, const std::string& p_ip, boost::uint16_t p_port, const std::string& p_string);

private:

    // Create the output file if needed
    void init();

private:

    // the name of the log file if we use one
    const std::string& m_logName;

    // the ofstream to use if we log to file
    std::ofstream m_fileStream;
};

#endif