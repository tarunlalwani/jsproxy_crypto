#include "session_parser.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include <fstream>
#include <stdexcept>

#include "md4.hpp"
#include "des.hpp"
#include "sha1.hpp"

namespace
{
    /*
     * Find the \r\n\r\n that denotes the end of the HTTP header and move the
     * provided string to just passed that location
     */
    bool moveToPayload(std::string& p_packet)
    {
        std::size_t offset = p_packet.find("\r\n\r\n");
        if (offset == std::string::npos) {
            return false;
        }
        p_packet.erase(0, offset + 4);
        return true;
    }

    /*
     * A c++ version of javascript's codePointAt. Only supports the two byte
     * version. Also, incremented index so that the caller can track how many
     * bytes were consumed (0, 1, or 2).
     */
    boost::uint8_t codePointAt(const std::string& p_seq, std::size_t& index)
    {
        char c1 = p_seq[index];
        if (c1 & 0x80) {
            if ((c1 & 0xf0) != 0xc0) {
                throw std::runtime_error("Unhandled unicode size");
            }
            if ((index + 1) >= p_seq.length()) {
                throw std::runtime_error("Not enough data in the string");
            }
            index++;
            if ((c1 & 0x0f) <= 2) {
                return p_seq[index++];
            }
            return p_seq[index++] | (1 << ((c1 & 0x0f) - 1 + 4));
        }
        index++;
        return c1;
    }

    void printHexString(const std::string& p_string, bool p_endl=true)
    {
        for (std::size_t i = 0; i < p_string.length(); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << (static_cast<boost::uint32_t>(p_string[i]) & 0xff);
        }
        if (p_endl) {
            std::cout << std::endl;
        }
    }
}

SessionParser::SessionParser(std::string& p_masterKey) :
    m_serverAddress(),
    m_state(k_none),
    m_split(),
    m_rx(),
    m_tx()
{
    // generate the send and receive RC4 contexts
    for (int i = 0; i < 40; ++i) {
        p_masterKey.push_back(0);
    }

    std::string server_key(p_masterKey);
    server_key.append("On the client side, this is the receive key; on the server side, it is the send key.");
    std::string client_key(p_masterKey);
    client_key.append("On the client side, this is the send key; on the server side, it is the receive key.");

    for (int i = 0; i < 40; ++i) {
        server_key.push_back(0xf2);
        client_key.push_back(0xf2);
    }

    unsigned char clientsha[20] = { 0 };
    sha1::calc(client_key.data(), client_key.size(), clientsha);
    client_key.assign((char*)clientsha, 16);

    unsigned char serversha[20] = { 0 };
    sha1::calc(server_key.data(), server_key.size(), serversha);
    server_key.assign((char*)serversha, 16);

    m_rx.setKey(server_key);
    m_tx.setKey(client_key);
}

SessionParser::~SessionParser()
{
}

void SessionParser::parse(const boost::uint8_t* p_data, boost::uint16_t p_length, boost::uint32_t p_srcAddr)
{
    switch(m_state) {
        case k_none:
            if (p_length > 13 && memcmp(p_data, "POST /jsproxy", 13) == 0) {
                std::cout << "[+] Initial request found." << std::endl;
                m_state = k_request;
            }
            break;
        case k_request:
            if (p_length > 17 && memcmp(p_data, "HTTP/1.1 200 OK\r\n", 17) == 0) {
                std::cout << "[+] Server challenge received." << std::endl;
                m_serverAddress = p_srcAddr;
                m_state = k_challenge;
            }
            break;
        case k_challenge:
            if (p_length < 13 || memcmp(p_data, "POST /jsproxy", 13) != 0) {
                break;
            }
            std::cout << "[+] Challenge response found." << std::endl;
            m_state = k_decrypt;
            break;
        case k_decrypt:
        {
            if (p_length > 13 && memcmp(p_data, "POST /jsproxy", 13) == 0) {
                std::string packet;
                packet.assign(reinterpret_cast<const char*>(p_data), p_length);
                if (moveToPayload(packet)) {

                    std::size_t index = 0;
                    for (std::size_t i = 0; i < 8; i++) {
                        codePointAt(packet, index);
                    }

                    std::string converted;
                    packet.erase(0, index);
                    for (index = 0; index < packet.length(); ) {
                        int codePoint = codePointAt(packet, index) & 0xff;
                        converted.push_back(codePoint);
                    }

                    std::cout << "Client decrypted: " << std::endl;
                    std::string decrypted = m_tx.decrypt(converted, 0);
                    std::cout << decrypted << std::endl;
                }
            } else if (p_length > 17 && memcmp(p_data, "HTTP/1.1 200 OK\r\n", 17) == 0) {
                std::string packet;
                packet.assign(reinterpret_cast<const char*>(p_data), p_length);
                if (moveToPayload(packet)) {
                    std::size_t index = 0;
                    for (std::size_t i = 0; i < 8; i++) {
                        codePointAt(packet, index);
                    }

                    std::string converted;
                    packet.erase(0, index);
                    for (index = 0; index < packet.length(); ) {
                        int codePoint = 0;
                        try {
                            codePoint = codePointAt(packet, index) & 0xff;
                            converted.push_back(codePoint);
                        } catch (const std::exception& e) {
                            if (index == (packet.length() - 1)) {
                                m_split = packet[packet.length() - 1];
                            } else {
                                std::cerr << e.what() << std::endl;
                            }
                            break;
                        }
                    }
                    std::cout << "Server decrypted: " << std::endl;
                    std::string decrypted = m_rx.decrypt(converted, 0);
                    std::cout << decrypted << std::endl;
                }
            } else if (m_serverAddress == p_srcAddr) {
                std::string packet;
                packet.assign(reinterpret_cast<const char*>(p_data), p_length);
                std::string converted;
                std::size_t index = 0;
                if (m_split != 0) {
                    std::cout << std::hex << (int)m_split << std::endl;
                    packet.insert(0, 1, m_split);
                    m_split = 0;
                }
                std::cout << std::hex << (int)packet[0] << std::endl;
                for (index = 0; index < packet.length(); ) {
                    int codePoint = 0;
                    try {
                        codePoint = codePointAt(packet, index) & 0xff;
                        converted.push_back(codePoint);
                    } catch (const std::exception& e) {
                        if (index == (packet.length() - 1)) {
                            m_split = packet[packet.length() - 1];
                        } else {
                            std::cerr << e.what() << std::endl;
                        }
                        break;
                    }
                }
                std::cout << "Server decrypted: " << std::endl;
                std::string decrypted = m_rx.decrypt(converted, 0);
                std::cout << decrypted << std::endl;
            } else {
                std::string packet;
                packet.assign(reinterpret_cast<const char*>(p_data), p_length);
                std::string converted;
                std::size_t index = 0;
                for (index = 0; index < packet.length(); ) {
                    int codePoint = codePointAt(packet, index) & 0xff;
                    converted.push_back(codePoint);
                }
                std::cout << "Client decrypted: " << std::endl;
                std::string decrypted = m_tx.decrypt(converted, 0);
                std::cout << decrypted << std::endl;
            }
        }
        case k_done:
        default:
            break;
    }
}

