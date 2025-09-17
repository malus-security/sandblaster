#include "string_utils.hpp"

std::string quote_string(const std::string &a)
{
	std::string ans = "\"";

	for (char c : a) {
		if (c == '"') {
			ans += '\\';
		}

		ans += c;
	}

	return ans + '"';
}
