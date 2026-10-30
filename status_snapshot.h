#pragma once
#include <algorithm>
#include <cstdint>
#include <mutex>
#include <vector>

struct KozHardwareStatusEntry {std::uintptr_t address;unsigned slot;};
// Diagnostic copy only. No debugger APIs or logging run while this lock is held.
class KozHardwareStatus {
 std::mutex mutex_;
 std::vector<KozHardwareStatusEntry> entries_;
public:
 void set(std::uintptr_t address,unsigned slot) {
  std::lock_guard<std::mutex> lock(mutex_);
  for(auto& entry:entries_)if(entry.address==address){entry.slot=slot;return;}
  entries_.push_back({address,slot});
 }
 void erase(std::uintptr_t address) {
  std::lock_guard<std::mutex> lock(mutex_);
  entries_.erase(std::remove_if(entries_.begin(),entries_.end(),[&](const KozHardwareStatusEntry& e){return e.address==address;}),entries_.end());
 }
 void clear(){std::lock_guard<std::mutex> lock(mutex_);entries_.clear();}
 std::vector<KozHardwareStatusEntry> snapshot(){std::lock_guard<std::mutex> lock(mutex_);return entries_;}
};
