#pragma once
// A preflight rejection must not deactivate the existing handlers.
template<class Armed,class Prepare>
bool kozBeginDisarm(Armed& activeState,Prepare prepare) {
 if(!prepare())return false;
 activeState=false;
 return true;
}
// Settings must not change while old-profile recovery is still pending.
// Once teardown has begun, an installation failure leaves the target paused
// and the attempted profile inactive; it must not be persisted as successful.
template<class Prepare,class Select,class Activate,class Save>
bool kozChangeConfiguration(Prepare prepare,Select select,Activate activate,Save save) {
 if(!prepare())return false;
 select();
 if(!activate())return false;
 return save();
}

