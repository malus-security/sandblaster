#pragma once

#include <string>
#include <unordered_map>
#include <vector>

class StringHasher {
  public:
	int m_clean_id;
	std::unordered_map<std::string, int> m_hashmap;
	std::vector<std::string> m_rev_hashmap;

  public:
	StringHasher();

	int hash(std::string str);

	std::string reverse_hash(int hash);
};
