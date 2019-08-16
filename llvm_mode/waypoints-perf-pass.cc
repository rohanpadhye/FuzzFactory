#include "fuzzfactory.hpp"
using namespace fuzzfactory;

class PerfFuzzFeedback : public DomainFeedback<PerfFuzzFeedback> {
public:
    PerfFuzzFeedback(Module& M) : DomainFeedback<PerfFuzzFeedback>(M, "__afl_perf_dsf") { }

    void visitBasicBlock (BasicBlock &bb) {
        auto key = createProgramLocation(); // static random value
        
        // Insert call to `dsf_increment(dsf_map, key, 1)`;
        auto irb = insert_before(bb); // Get a handle to the LLVM IR builder
        irb.CreateCall(DsfIncrementFunction, {DsfMapVariable, key, getConst(1)}); 
    }
};

FUZZFACTORY_REGISTER_DOMAIN(PerfFuzzFeedback);
