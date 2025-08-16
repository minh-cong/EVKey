CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra

TEST_DIR := tests
TEST_BIN := $(TEST_DIR)/split_wstring_test

.PHONY: test clean

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_DIR)/split_wstring_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(TEST_BIN)
