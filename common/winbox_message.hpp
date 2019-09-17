/*
  Copyright 2018 Tenable, Inc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                *

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
#ifndef WINBOX_MESSAGE_HPP
#define WINBOX_MESSAGE_HPP

#include <map>
#include <vector>
#include <string>
#include <boost/array.hpp>
#include <boost/cstdint.hpp>

/*!
 * \brief An implementation of the RouterOS nv::Message.
 *
 * This object represents the RouterOS nv::Message. It can parse in a message in
 * JSON format (webfig) or in the binary format (webfig and winbox). It can
 * also serialize the message into the binary format as well as the JSON format
 * (although the JSON version is not perfect).
 */
class WinboxMessage
{
public:

    /*!
     * Default constructor
     */
    WinboxMessage();

    /*!
     * Default deconstructor
     */
    ~WinboxMessage();

    /*!
     * Clears all the member variables.
     * Effecitvely returns the object to the default constructor state.
     */
    void reset();

    /*!
     * Converts the object into a binary format for network communication.
     * 
     * \return the binary representation of the data
     */
    std::string serialize_to_binary() const;

    /*!
     * Converts the object into a JSON format for network communication.
     *
     * \return the binary representation of the data
     */
    std::string serialize_to_json() const;

    /*!
     * Parses a binary WinboxMessage
     * Parses the provided data and stores the results in member variables.
     *
     * \note This is vulnerable to a stack overflow due to recusion within
     *       message variables. The irony is that I reported that exact bug
     *       to Mikrotik. However, I currently have no plans to alter the
     *       implementation.
     * 
     * \param[in] p_input the data to convert into a WinboxMessage
     * \return true if successful and false otherwise
     */
    bool parse_binary(const std::string& p_input);

    /*!
     * Parses a JSON WinboxMessage
     * Parses the provided data and stores the results in member variables.
     *
     * \note This JSON parser has some serious shortcomings due to its
     *       complete reliance on regular expressions to parse data.
     *       I've justified this by first accepting that the JSON format of the
     *       nv::Message seems little used by modern RouterOS. Also the JSON
     *       isn't even well formed. So please excuse that this isn't a fool
     *       proof implementation
     * 
     * \param[in] p_input the data to convert into a WinboxMessage
     * \return true if successful and false otherwise
     */
    bool parse_json(const std::string& p_input);

    /*!
     * Returns true if an error parameter is present
     *
     * \return true if an error is present. false otherwise.
     */
    bool has_error() const;

    /*!
     * Returns the provided error message or builtin error message corresponding
     * to the error number.
     *
     * \return a string indicating the error
     */
    std::string get_error_string() const;

    /*!
     * Returns the session ID.
     *
     * \return the session ID
     */
    boost::uint32_t get_session_id() const;

    /*!
     * Returns the value of a boolean variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    bool get_boolean(boost::uint32_t p_name) const;

    /*!
     * Returns the value of a 32 bit variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    boost::uint32_t get_u32(boost::uint32_t p_name) const;

    /*!
     * Returns the value of a 64 bit variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    boost::uint64_t get_u64(boost::uint32_t p_name) const;

    /*!
     * Returns the value of an IPv6 variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    boost::array<unsigned char, 16> get_ip6(boost::uint32_t p_name) const;

    /*!
     * Returns the value of a string variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    std::string get_string(boost::uint32_t p_name) const;

    /*!
     * Returns the value of a message variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    WinboxMessage get_msg(boost::uint32_t p_name) const;

    /*!
     * Returns the value of a raw variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    std::string get_raw(boost::uint32_t p_name) const;

    /*!
     * Returns the value of a boolean array variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    std::vector<bool> get_boolean_array(boost::uint32_t p_name) const;

    /*!
     * Returns the value of a 32 bit array variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    std::vector<boost::uint32_t> get_u32_array(boost::uint32_t p_name) const;

    /*!
     * Returns the value of a 64 bit array variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    std::vector<boost::uint64_t> get_u64_array(boost::uint32_t p_name) const;

    /*!
     * Returns the value of an IPv6 array variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    std::vector<boost::array<unsigned char, 16> > get_ip6_array(boost::uint32_t p_name) const;

    /*!
     * Returns the value of a string array variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    std::vector<std::string> get_string_array(boost::uint32_t p_name) const;

    /*!
     * Returns the value of a message array variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    std::vector<WinboxMessage> get_msg_array(boost::uint32_t p_name) const;

    /*!
     * Returns the value of a raw array variable.
     *
     * \param[in] p_name the name of the variable (ie. 0xff0007)
     * \return the stored value for the provided variable
     */
    std::vector<std::string> get_raw_array(boost::uint32_t p_name) const;

    /*!
     * Sets the messages "to" variable.
     * This controls where the message will be routed to in RouterOS
     *
     * \param[in] p_to The integer representing the binary to send to
     */
    void set_to(boost::uint32_t p_to);

    /*!
     * Sets the messages "to" variable.
     * This controls where the message will be routed to in RouterOS
     *
     * \param[in] p_to The integer representing the binary to send to
     * \param[in] p_handler The registered handler that should handle this message
     */
    void set_to(boost::uint32_t p_to, boost::uint32_t p_handler);

    /*!
     * Sets the command variable to the provided value.
     *
     * \param[in] p_command the command to execute
     */
    void set_command(boost::uint32_t p_command);

    /*!
     * Sets the reply expected variable to the provided value.
     *
     * \param[in] p_reply_expected true if we expect a reply and false otherwise
     */
    void set_reply_expected(bool p_reply_expected);

    /*!
     * Sets the request ID for the message.
     * The server will include this ID in the response.
     *
     * \param[in] p_id the ID for the request.
     */
    void set_request_id(boost::uint32_t p_id);

    /*!
     * Sets the messages session ID variable.
     * The first message won't need a message ID, but every subsequent message
     * does need one. The server will respond with it in the first reply
     *
     * \param[in] p_to The integer representing the session ID
     */
    void set_session_id(boost::uint32_t p_session_id);

    /*!
     * Adds a new boolean value to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_boolean(boost::uint32_t p_name, bool p_value);

    /*!
     * Adds a new 32 bit value to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_u32(boost::uint32_t p_name, boost::uint32_t p_value);

    /*!
     * Adds a new 64 bit value to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_u64(boost::uint32_t p_name, boost::uint64_t p_value);

    /*!
     * Adds a new IPv6 value to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_ip6(boost::uint32_t p_name, boost::array<unsigned char, 16> p_value);

    /*!
     * Adds a new string value to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_string(boost::uint32_t p_name, const std::string& p_string);

    /*!
     * Adds a new message value to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_msg(boost::uint32_t p_name, const WinboxMessage& p_msg);

    /*!
     * Adds a new raw value to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_raw(boost::uint32_t p_name, const std::string& p_raw);

    /*!
     * Adds a new boolean array to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_boolean_array(boost::uint32_t p_name, const std::vector<bool>& p_value);

    /*!
     * Adds a new 32 bit array to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_u32_array(boost::uint32_t p_name, const std::vector<boost::uint32_t>& p_value);

    /*!
     * Adds a new 64 bit array to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_u64_array(boost::uint32_t p_name, const std::vector<boost::uint64_t>& p_value);

    /*!
     * Adds a new IPv6 array to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_ip6_array(boost::uint32_t p_name, const std::vector<boost::array<unsigned char, 16> >& p_value);

    /*!
     * Adds a new string array to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_string_array(boost::uint32_t p_name, const std::vector<std::string>& p_value);

    /*!
     * Adds a new message array to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_msg_array(boost::uint32_t p_name, const std::vector<WinboxMessage>& p_value);

    /*!
     * Adds a new raw array to the message
     *
     * \param[in] p_name the variables name (ie. 0xff0007)
     * \param[in] p_value the variable's value
     */
    void add_raw_array(boost::uint32_t p_name, const std::vector<std::string>& p_value);

    void erase_u32(boost::uint32_t p_name);

private:

    //! The boolean variable mapping
    std::map<boost::uint32_t, bool> m_bools;

    //! The 32 bit integer variable mapping
    std::map<boost::uint32_t, boost::uint32_t> m_u32s;

    //! The 64 bit integer variable mapping
    std::map<boost::uint32_t, boost::uint64_t> m_u64s;

    //! The IPv6 variable mapping
    std::map<boost::uint32_t, boost::array<unsigned char, 16> > m_ip6s;

    //! The strings variable mapping
    std::map<boost::uint32_t, std::string> m_strings;

    //! The message variable mapping
    std::map<boost::uint32_t, WinboxMessage> m_msgs;

    //! The raw variable mapping
    std::map<boost::uint32_t, std::string> m_raw;

    //! The bool array variable mapping
    std::map<boost::uint32_t, std::vector<bool> > m_bool_array;

    //! The 32 bit integer array variable mapping
    std::map<boost::uint32_t, std::vector<boost::uint32_t> > m_u32_array;

    //! The 64 bit integer array variable mapping
    std::map<boost::uint32_t, std::vector<boost::uint64_t> > m_u64_array;

    //! The IPv6 array variable mapping
    std::map<boost::uint32_t, std::vector<boost::array<unsigned char, 16> > > m_ip6_array;

    //! The string array variable mapping
    std::map<boost::uint32_t, std::vector<std::string> > m_string_array;

    //! The message array variable mapping
    std::map<boost::uint32_t, std::vector<WinboxMessage> > m_msg_array;

    //! The raw array variable mapping
    std::map<boost::uint32_t, std::vector<std::string> > m_raw_array;
};

#endif
