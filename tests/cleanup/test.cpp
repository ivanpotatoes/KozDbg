#undef NDEBUG
#include <cassert>
#include <vector>
#include <cstdio>
#include "../../retry_cleanup.h"
int main() {
 std::vector<int> records{1,2,3,4},attempts;
 // Simulate failed deletion and failed readback among successful operations.
 assert(!kozRetryCleanup(records,[&](int id){attempts.push_back(id);return id==1||id==3;}));
 assert((attempts==std::vector<int>{1,2,3,4}));
 assert((records==std::vector<int>{2,4}));
 attempts.clear();
 assert(!kozRetryCleanup(records,[&](int id){attempts.push_back(id);return false;}));
 assert((attempts==std::vector<int>{2,4}));
 assert((records==std::vector<int>{2,4}));
 attempts.clear();
 assert(kozRetryCleanup(records,[&](int id){attempts.push_back(id);return true;}));
 assert((attempts==std::vector<int>{2,4}));
 assert(records.empty());
 assert(kozRetryCleanup(records,[](int){assert(false);return false;}));
 puts("PASS: partial failure, retained obligations, repeated failure, retry, empty cleanup");
}
