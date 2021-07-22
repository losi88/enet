#ifndef __ENET_SSL_COMMON_H__
#define __ENET_SSL_COMMON_H__

/*
 * @Author: Dash Zhou
 * @Date: 2019-03-27 18:28:04
 * @Last Modified by:   Dash Zhou
 * @Last Modified time: 2019-03-27 18:28:04
 */

#include <iostream>
#include <string>
#include "enet/ssl/ecdh.h"

namespace common
{
	template<class Elem, class Traits>
	inline void hex_dump(const void* aData, std::size_t aLength, std::basic_ostream<Elem, Traits>& aStream, std::size_t aWidth = 16)
	{
		const char* const start = static_cast<const char*>(aData);
		const char* const end = start + aLength;
		const char* line = start;
		while (line != end)
		{
			aStream << "    ";
			aStream.width(4);
			aStream.fill('0');
			aStream << std::hex << line - start << " : ";
			std::size_t lineLength = (aWidth < static_cast<std::size_t>(end - line)) ? aWidth : static_cast<std::size_t>(end - line);
			for (std::size_t pass = 1; pass <= 2; ++pass)
			{
				for (const char* next = line; next != end && next != line + aWidth; ++next)
				{
					char ch = *next;
					switch (pass)
					{
					case 1:
						aStream << (ch < 32 ? '.' : ch);
						break;
					case 2:
						if (next != line)
							aStream << " ";
						aStream.width(2);
						aStream.fill('0');
						aStream << std::hex << std::uppercase << static_cast<int>(static_cast<unsigned char>(ch));
						break;
					}
				}
				if (pass == 1 && lineLength != aWidth)
					aStream << std::string(aWidth - lineLength, ' ');
				aStream << " ";
			}
			aStream << std::endl;
			line = line + lineLength;
		}
	}

	inline void hex_dump(const std::string &data)
	{
		hex_dump(data.data(), data.size(), std::cout);
	}
	
	inline std::string hex_to_ascii_string(std::string const& keyHex)
	{
		size_t len = keyHex.size();
		std::string newString;
		for (int i = 0; i < len; i += 2)
		{
			std::string byte = keyHex.substr(i, 2);
			char chr = (char)(int)strtol(byte.c_str(), 0, 16);
			newString.push_back(chr);
		}
		return newString;
	}
}

#endif
