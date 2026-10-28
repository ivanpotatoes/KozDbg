#pragma once
#include <algorithm>
#include <cstddef>
#include <vector>

// Fixed memory use. One-byte lookahead preserves 0F 05 across block boundaries.
// Every candidate offset is visited once; sections never share lookahead bytes.
template<class Reader,class Match>
bool kozScanChunks(size_t length,Reader reader,Match match){
 constexpr size_t block=1024*1024;
 std::vector<unsigned char> bytes((std::min)(length,block+1));
 for(size_t offset=0;offset<length;){
  const size_t step=(std::min)(block,length-offset);
  const size_t count=step+(length-offset>step?1:0);
  if(!reader(offset,bytes.data(),count))return false;
  for(size_t i=0;i<step&&i+1<count;i++)
   if(bytes[i]==0x0f&&bytes[i+1]==0x05&&!match(offset+i))return false;
  offset+=step;
 }
 return true;
}
