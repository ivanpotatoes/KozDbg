#undef NDEBUG
#include <cassert>
#include <cstdio>
#include "../../x86_abi.h"
int main(){
 uint32_t result=0;
 assert(kozX86ReturnStack(0x1000,0,result)&&result==0x1004);
 assert(kozX86ReturnStack(0x1000,1,result)&&result==0x1008);
 assert(kozX86ReturnStack(0x1000,2,result)&&result==0x100c);
 assert(kozX86ReturnStack(0x1000,4,result)&&result==0x1014);
 assert(kozX86ReturnStack(0x1000,5,result)&&result==0x1018);
 assert(!kozX86ReturnStack(0xfffffff0,5,result));
 assert(!kozX86ReturnStack(0x1000,0xffffffff,result));
 puts("PASS: x86 stdcall return stack for all hooked signatures and overflow rejection");
}
