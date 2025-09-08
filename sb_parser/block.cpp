#include <algorithm>
#include <cstdio>

#include "block.hpp"
#include "hasher.hpp"
#include "string_utils.hpp"

Block::Block(StringHasher &hasher)
{
	this->m_name = 0;

	this->m_hasher = &hasher;
}

void Block::set_name(std::string str)
{
	this->m_name = this->m_hasher->hash(str);
}

void Block::add_attr(std::string attr)
{
	this->m_attributes.push_back(this->m_hasher->hash(attr));
}

void Block::add_child(Block *other) { this->m_children.push_back(other); }

std::string Block::to_string()
{
	std::string name = this->m_hasher->reverse_hash(this->m_name);

	std::string ans = "{\"name\": " + quote_string(name);

	ans += ", \"attributes\": [";
	if (!this->m_attributes.empty()) {
		for (int attribute : this->m_attributes) {
			ans += quote_string(this->m_hasher->reverse_hash(attribute)) + ",";
		}

		ans.pop_back();
	}
	ans += "], \"children\": [";
	if (!this->m_children.empty()) {
		for (Block *child_block_ptr : this->m_children) {
			ans += child_block_ptr->to_string() + ",";
		}
		ans.pop_back();
	}
	ans += "]";

	ans += "}";
	return ans;
}

// todo maybe add comparator options here
int Block::compare_to(Block *other, bool skip_print)
{
	//* check name first
	if (this->m_name != other->m_name) {
		if (!skip_print) {
			std::fprintf(stderr, "Block names differ: '%s' vs '%s'\n",
						 this->m_hasher->reverse_hash(this->m_name).c_str(),
						 other->m_hasher->reverse_hash(other->m_name).c_str());
		}

		return this->m_name - other->m_name;
	}

	//* check attributes
	//* check size first, if this fails, no need to sort
	if (this->m_attributes.size() != other->m_attributes.size()) {
		if (!skip_print) {
			std::fprintf(stderr,
						 "Block attribute lengths differ: '%lu' vs '%lu'\n",
						 this->m_attributes.size(), other->m_attributes.size());
		}

		return ((int)(this->m_attributes.size())) -
			   ((int)(other->m_attributes.size()));
	}

	//* check attribute values, sort first because order doesn't matter
	std::sort(this->m_attributes.begin(), this->m_attributes.end());
	std::sort(other->m_attributes.begin(), other->m_attributes.end());

	for (int i = 0; i < (int)(this->m_attributes.size()); ++i) {
		if (this->m_attributes[i] != other->m_attributes[i]) {
			if (!skip_print) {
				std::fprintf(
					stderr, "Block attribute #%d differs: '%s' vs '%s'\n", i,
					this->m_hasher->reverse_hash(this->m_attributes[i]).c_str(),
					other->m_hasher->reverse_hash(other->m_attributes[i])
						.c_str());
			}
			return this->m_attributes[i] - other->m_attributes[i];
		}
	}

	//* check children
	//* check size first, if this fails, no need to sort
	if (this->m_children.size() != other->m_children.size()) {
		if (!skip_print) {
			std::fprintf(stderr,
						 "Block children lengths differ: '%lu' vs '%lu'\n",
						 this->m_children.size(), other->m_children.size());
		}
		return ((int)(this->m_children.size())) -
			   ((int)(other->m_children.size()));
	}

	auto block_comparator = [](Block *i, Block *j) -> bool {
		return i->compare_to(j, true) < 0;
	};

	std::sort(this->m_children.begin(), this->m_children.end(),
			  block_comparator);
	std::sort(other->m_children.begin(), other->m_children.end(),
			  block_comparator);

	for (int i = 0; i < (int)(this->m_children.size()); ++i) {
		int result =
			this->m_children[i]->compare_to(other->m_children[i], skip_print);

		if (result != 0) {
			if (!skip_print) {
				std::fprintf(
					stderr,
					"Block child #%d differs: '%s' vs '%s' (see above error)\n",
					i,
					this->m_hasher->reverse_hash(this->m_children[i]->m_name)
						.c_str(),
					other->m_hasher->reverse_hash(other->m_children[i]->m_name)
						.c_str());
			}
			return result;
		}
	}

	//* if all checks pass, objects are equal
	return 0;
}

Block::~Block()
{
	for (Block *child_block_ptr : this->m_children) {
		delete child_block_ptr;
	}
}
