#undef NDEBUG
#include <cassert>
#include <atomic>
#include <cstdio>
#include "../../profile_transition.h"
int main() {
 std::atomic<bool> armed{true};
 unsigned profile=331,options=8191,saved=331,installCalls=0;
 bool ready=false;
 auto prepare=[&]{return kozBeginDisarm(armed,[&]{return ready;});};
 auto select=[&]{profile=380;options=7;};
 auto activate=[&]{++installCalls;armed=true;return true;};
 auto save=[&]{saved=profile;return true;};
 assert(!kozChangeConfiguration(prepare,select,activate,save));
 assert(armed&&profile==331&&options==8191&&saved==331&&installCalls==0);
 // A repeated rejection also leaves an already inactive session inactive.
 armed=false;
 assert(!kozChangeConfiguration(prepare,select,activate,save));
 assert(!armed&&profile==331&&saved==331&&installCalls==0);
 armed=true;ready=true;
 assert(kozChangeConfiguration(prepare,select,activate,save));
 assert(armed&&profile==380&&options==7&&saved==380&&installCalls==1);
 // Installation failure after teardown cannot claim that old protection lives.
 assert(!kozChangeConfiguration(prepare,[&]{profile=394;},[]{return false;},save));
 assert(!armed&&profile==394&&saved==380);
 // Disabling follows the same preflight gate and persists only after success.
 ready=false;armed=true;bool enabled=true;
 assert(!kozChangeConfiguration(prepare,[&]{enabled=false;},[]{return true;},save));
 assert(enabled&&armed);
 ready=true;
 assert(kozChangeConfiguration(prepare,[&]{enabled=false;},[]{return true;},save));
 assert(!enabled&&!armed);
 assert(!kozChangeConfiguration(prepare,select,activate,[]{return false;}));
 assert(armed&&profile==380);
 puts("PASS: rejected switch/disable, retained state, retry, install failure, successful disable");
}
