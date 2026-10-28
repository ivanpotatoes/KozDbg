#pragma once
#include <cstdint>
// DBG_REPLY_LATER applies only to an exception belonging to this debug event.
// Never reinterpret a genuine exception or an event from a different thread.
constexpr std::uint32_t kozNormalizeContinueStatus(std::uint32_t process,std::uint32_t thread,
 std::uint32_t eventProcess,std::uint32_t eventThread,std::uint32_t eventCode,std::uint32_t status) {
 return process==eventProcess&&thread==eventThread&&eventCode>=2&&eventCode<=9&&status==0x40010001u
  ?0x00010002u:status;
}
