#undef NDEBUG
#include <cassert>
#include <atomic>
#include <thread>
#include <cstdio>
#include "../../status_snapshot.h"
int main() {
 KozHardwareStatus state;
 state.set(0x1000,0);
 const auto old=state.snapshot();
 state.set(0x1000,3);
 assert(state.snapshot().size()==1&&state.snapshot()[0].slot==3);
 state.erase(0x1000);
 assert(state.snapshot().empty()&&old.size()==1&&old[0].slot==0);
 state.erase(0x1000);
 std::atomic<bool> start{false};
 std::atomic<unsigned> reads{0};
 auto reader=[&]{
  while(!start.load())std::this_thread::yield();
  for(unsigned i=0;i<50000;++i){
   const auto snapshot=state.snapshot();
   assert(snapshot.size()<=4);
   for(size_t j=0;j<snapshot.size();++j){
    assert(snapshot[j].slot<4&&snapshot[j].address>=0x1000&&snapshot[j].address<0x1004);
    for(size_t k=j+1;k<snapshot.size();++k)assert(snapshot[j].address!=snapshot[k].address);
   }
   ++reads;
  }
 };
 std::thread first(reader),second(reader);
 std::thread writer([&]{
  while(!start.load())std::this_thread::yield();
  for(unsigned i=0;i<50000;++i){
   state.set(0x1000+i%4,i%4);
   if(i%3==0)state.erase(0x1000+(i+1)%4);
   if(i%17==0)state.clear();
  }
 });
 start=true;first.join();second.join();writer.join();
 assert(reads==100000);
 state.clear();assert(state.snapshot().empty());
 puts("PASS: detached snapshots, update/remove/reset, 100000 concurrent status reads");
}
