#include "fuzzfactory.hpp"
using namespace fuzzfactory;

class SlowFuzzFeedback : public DomainFeedback<SlowFuzzFeedback> {
public:
    SlowFuzzFeedback(Module& M) : DomainFeedback<SlowFuzzFeedback>(M, "__afl_slow_dsf") { }

    void visitBasicBlock (BasicBlock &bb) {
        // Insert call to `dsf_increment(dsf_map, 0, 1)`;
        auto irb = insert_before(bb); // Get a handle to the LLVM IR Builder at this point
        irb.CreateCall(DsfIncrementFunction, {DsfMapVariable, getConst(0), getConst(1)}); 
    }
};

FUZZFACTORY_REGISTER_DOMAIN(SlowFuzzFeedback);
