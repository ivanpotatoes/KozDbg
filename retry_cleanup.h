#pragma once
// Retain failed obligations for retry while releasing independent resources.
template<class Container,class Cleanup>
bool kozRetryCleanup(Container& records,Cleanup cleanup) {
 bool complete=true;
 for(auto it=records.begin();it!=records.end();) {
  if(cleanup(*it))it=records.erase(it);
  else {complete=false;++it;}
 }
 return complete;
}
