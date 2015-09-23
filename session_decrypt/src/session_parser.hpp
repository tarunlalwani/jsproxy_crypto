#ifndef SESSION_PARSER_HPP
#define SESSION_PARSER_HPP

#include <string>
#include <boost/cstdint.hpp>

#include "rc4.hpp"

class SessionParser
{
private:

    enum session_state {
        k_none,
        k_request,
        k_challenge,
        k_decrypt,
        k_done
    };

public:
    SessionParser(std::string& p_masterKey);
    ~SessionParser();

    void parse(const boost::uint8_t* p_data, boost::uint16_t p_length, boost::uint32_t p_srcAddr);

private:

    boost::uint32_t m_serverAddress;
    session_state m_state;

    // a shameful hack
    boost::uint8_t m_split;

    RC4 m_rx;
    RC4 m_tx;

};

#endif