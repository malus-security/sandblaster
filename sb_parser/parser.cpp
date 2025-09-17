#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "block.hpp"
#include "hasher.hpp"

namespace fs = std::filesystem;

typedef enum { STATE_IDLE, STATE_READING_NAME, STATE_READING_ATTR } state_t;

Block *parse_sb_file(std::ifstream &stream, StringHasher &hasher)
{
	Block *root = new Block(hasher);
	root->set_name("root");

	std::vector<Block *> block_stack;
	block_stack.push_back(root);

	state_t state = STATE_IDLE;
	std::string curr_token = "";

	while (!stream.eof()) {
		char c = stream.get();

		// brackets mean changing current block
		if (c == '(' || c == ')') {
			if (!curr_token.empty()) {
				if (state == STATE_READING_NAME) {
					block_stack.back()->set_name(curr_token);
					state = STATE_READING_ATTR;
				}
				else if (state == STATE_READING_ATTR) {
					block_stack.back()->add_attr(curr_token);
				}

				curr_token.clear();
			}

			state = STATE_READING_NAME;
			if (c == '(') {
				Block *new_block = new Block(hasher);
				block_stack.push_back(new_block);
			}
			else {
				Block *current_block_ptr = block_stack.back();
				block_stack.pop_back();

				if (!block_stack.empty()) {
					Block *prev_block_ptr = block_stack.back();
					prev_block_ptr->add_child(current_block_ptr);
				}
			}

			continue;
		}

		// space means token end
		if (c == ' ' || c == '\n' || c == '\t') {
			if (curr_token.empty()) {
				continue;
			}

			if (state == STATE_READING_NAME) {
				block_stack.back()->set_name(curr_token);
				state = STATE_READING_ATTR;
			}
			else if (state == STATE_READING_ATTR) {
				block_stack.back()->add_attr(curr_token);
			}

			curr_token.clear();
			continue;
		}

		curr_token += c;
	}

	return root;
}

void collect_files(const std::string &dir, std::vector<fs::path> &sb_files,
				   std::vector<fs::path> &other_files)
{
	for (auto &path : fs::recursive_directory_iterator(dir)) {
		if (!path.is_regular_file()) {
			continue;
		}

		if (path.path().extension() == ".sb") {
			sb_files.push_back(fs::relative(path.path(), dir));
		}
		else {
			other_files.push_back(fs::relative(path.path(), dir));
		}
	}

	std::sort(sb_files.begin(), sb_files.end());
	std::sort(other_files.begin(), other_files.end());
}

bool structure_check(std::vector<fs::path> sb_files[2],
					 std::vector<fs::path> other_files[2])
{
	if (sb_files[0].size() != sb_files[1].size() ||
		other_files[0].size() != other_files[1].size()) {
		return false;
	}

	for (int i = 0; i < (int)(sb_files[0].size()); ++i) {
		if (sb_files[0][i] != sb_files[1][i]) {
			return false;
		}
	}

	for (int i = 0; i < (int)(other_files[0].size()); ++i) {
		if (other_files[0][i] != other_files[1][i]) {
			return false;
		}
	}

	return true;
}

bool files_equal(const fs::path &file1, const fs::path &file2)
{
	std::ifstream s1(file1);
	std::ifstream s2(file2);

	while (!s1.eof()) {
		if (s2.eof()) {
			return false;
		}

		char c1, c2;
		s1 >> c1;
		s2 >> c2;

		if (c1 != c2) {
			return false;
		}
	}

	return s2.eof();
}

bool sb_files_equal(const fs::path &file1, const fs::path &file2,
					StringHasher &hasher)
{
	std::ifstream s1(file1);
	std::ifstream s2(file2);

	Block *root1 = parse_sb_file(s1, hasher);
	Block *root2 = parse_sb_file(s2, hasher);

	return root1->compare_to(root2) == 0;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		std::cerr << "Usage: " << argv[0] << " file1.sb file2.sb" << std::endl;
		return 2;
	}

	const std::string dir1 = std::string(argv[1]);
	if (!fs::exists(dir1) || !fs::is_directory(dir1)) {
		std::cerr << "Invalid first directory: '" << dir1 << "' :(\n";
		return 2;
	}

	const std::string dir2 = std::string(argv[2]);
	if (!fs::exists(dir2) || !fs::is_directory(dir2)) {
		std::cerr << "Invalid first directory: '" << dir2 << "' :(\n";
		return 2;
	}

	std::vector<fs::path> sb_files[2];
	std::vector<fs::path> other_files[2];

	collect_files(dir1, sb_files[0], other_files[0]);
	collect_files(dir1, sb_files[1], other_files[1]);

	//* check filenames and structure
	if (!structure_check(sb_files, other_files)) {
		std::cerr << "Structure or filename mismatch :(\n";
		return 1;
	}

	//* check non-sb files first
	for (int i = 0; i < (int)(other_files[0].size()); ++i) {
		fs::path file1 = fs::path(dir1) / other_files[0][i];
		fs::path file2 = fs::path(dir2) / other_files[1][i];

		if (!files_equal(file1, file2)) {
			std::cerr << "Non-sb files differ: '" << other_files[0][i]
					  << "' :(\n";
			return 1;
		}
	}

	//* check sb files
	StringHasher main_hasher;

	for (int i = 0; i < (int)(sb_files[0].size()); ++i) {
		fs::path file1 = fs::path(dir1) / sb_files[0][i];
		fs::path file2 = fs::path(dir2) / sb_files[1][i];

		if (!sb_files_equal(file1, file2, main_hasher)) {
			std::cerr << "Sb files differ: " << sb_files[0][i] << " :(\n";
			return 1;
		}
	}

	//* return success if all checks pass
	return 0;
}
