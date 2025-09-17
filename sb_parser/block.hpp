#pragma once

#include <string>
#include <vector>

#include "hasher.hpp"

class Block {
  public:
	int m_name;
	std::vector<int> m_attributes;
	std::vector<Block *> m_children;

	StringHasher *m_hasher;

  public:
	Block(StringHasher &hasher);

	~Block();

	void set_name(std::string str);

	void add_attr(std::string str);

	void add_child(Block *child);

	std::string to_string();

	int compare_to(Block *other, bool skip_print = false);
};
