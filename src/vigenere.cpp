#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <ctype.h>

#include "../include/vigenere.hpp"
 

namespace cryptoAL_vigenere
{
    int myisalnum(int c)
    {
        if (c < 0 || c> 127) return 0;
        return isalnum(c);
    }

    int index(char c)
    {
	    for(int ii = 0; ii < (int)AVAILABLE_CHARS.size(); ii++)
	    {
		    if(AVAILABLE_CHARS[ii] == c)
		    {
			    return ii;
		    }
	    }
	    return -1;
    }

    bool is_valid_string(const std::string s)
    {
        char c;
        unsigned char v;
        for(int ii = 0; ii < (int)s.size(); ii++)
        {
            c = s[ii];
            if (index(c) == -1)
            {
                v = (unsigned char)c;
                if ((v >= 32) && (v <= 127))
                {
                    continue;
                }
                else
                {
                    std::cerr << "Invalid char at position: " << ii << std::endl;
                    return false;
                }
            }
        }
        return true;
    }

    bool is_string_ok(const std::string& s)
    {
        char c;
        for (int ii = 0; ii < (int)s.size(); ii++)
        {
            c = s[ii];
            if (index(c) == -1)
            {
                return false;
            }
        }
        return true;
    }

    std::string extend_key(const std::string& msg, const std::string& key)
    {
	    // generating new key
	    int msgLen = (int)msg.size();
	    std::string newKey(msgLen, 'x');

        int keyLen = (int)key.size();
        int i; int j;
	    keyLen = keyLen;

        for(i = 0, j = 0; i < msgLen; ++i, ++j)
        {
            if (j == keyLen)
                j = 0;

            newKey[i] = key[j];
        }
        newKey[i] = '\0';
	    return newKey;
    }


    std::string encrypt_vigenere(const std::string& msg, const std::string& key)
    {
	    int msgLen = (int)msg.size();
        int i = 0;

 	    std::string encryptedMsg(msgLen, 'x');
	    std::string newKey = extend_key(msg, key);

        //encryption
        for(i = 0; i < msgLen; ++i)
        {
    	    if( myisalnum(msg[i]) or msg[i] == ' ')
    	    {
    		    encryptedMsg[i] = AVAILABLE_CHARS[((index(msg[i]) + index(newKey[i])) % AVAILABLE_CHARS.size())];
    	    }
    	    else
    	    {
    		    encryptedMsg[i] = msg[i];
    	    }
        }

        encryptedMsg[i] = '\0';
        return encryptedMsg;
    }

    std::string decrypt_vigenere(const std::string& encryptedMsg, const std::string& newKey)
    {
	    // decryption
	    int msgLen = (int)encryptedMsg.size();
	    std::string decryptedMsg(msgLen, 'x');
	    int i;
        for(i = 0; i < msgLen; ++i)
        {
            //isalnum 0-127 The behavior is undefined if the value of ch is not representable as unsigned char and is not equal to EOF. 
    	    if(myisalnum(encryptedMsg[i]) or encryptedMsg[i] == ' ')
    	    {
    		    decryptedMsg[i] = AVAILABLE_CHARS[(((index(encryptedMsg[i]) - index(newKey[i])) + AVAILABLE_CHARS.size()) % AVAILABLE_CHARS.size())];
    	    }
    	    else
    	    {
    		    decryptedMsg[i] = encryptedMsg[i];
    	    }
        }
        decryptedMsg[i] = '\0';
	    return decryptedMsg;
    }

}


