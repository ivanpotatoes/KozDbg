#pragma once
#include <cstdint>
#include <limits>
inline bool kozX86ReturnStack(uint32_t stack,unsigned arguments,uint32_t& result){
 if(arguments>(std::numeric_limits<uint32_t>::max()/4)-1)return false;
 const uint32_t bytes=(arguments+1)*4;
 if(stack>std::numeric_limits<uint32_t>::max()-bytes)return false;
 result=stack+bytes;return true;
}
