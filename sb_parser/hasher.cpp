#include "hasher.hpp"

#include <stdexcept>
#include <string>
#include <unordered_map>

StringHasher::StringHasher()
{
	this->m_clean_id = 1;
	this->m_hashmap = std::unordered_map<std::string, int>();
	this->m_rev_hashmap = std::vector<std::string>();

	this->m_rev_hashmap.push_back("default-name"); // reverse hash of 0
}

int StringHasher::hash(std::string str)
{
	if (!this->m_hashmap.count(str)) {
		this->m_hashmap[str] = this->m_clean_id;
		this->m_rev_hashmap.push_back(str);
		++(this->m_clean_id);
	}

	return this->m_hashmap[str];
}

std::string StringHasher::reverse_hash(int hash)
{
	if (hash > this->m_rev_hashmap.size()) {
		throw std::runtime_error("cannot reverse " + std::to_string(hash) +
								 " : invalid hash");
	}

	return this->m_rev_hashmap[hash];
}
