#include "fuzzfactory.hpp"

using namespace fuzzfactory;

class MemAllocFeedback : public DomainFeedback<MemAllocFeedback> {
public:
    MemAllocFeedback(Module& M) : DomainFeedback<MemAllocFeedback>(M, "__afl_mem_dsf") { }

    void visitCallInst(CallInst& call) {
        Function* callee = call.getCalledFunction();
        if (!callee) { return; } // No callee for indirect calls

        if (callee->getName() == "malloc") { // Handle malloc
            auto key = createProgramLocation(); // static random value
            auto irb = insert_after(call); // Get a handle to the LLVM IR Builder at this point
            auto bytes = irb.CreateTrunc(call.getArgOperand(0), Int32Ty); // Cast size_t to int32

            // Insert call to dsf_increment(dsf_map, key, bytes);
            irb.CreateCall(DsfIncrementFunction, {DsfMapVariable, key, bytes}); 

        } else if (callee->getName() == "calloc") { // Handle calloc
            auto key = createProgramLocation(); // static random value
            auto irb = insert_after(call); // Get a handle to the LLVM IR Builder at this point
            auto bytes = irb.CreateTrunc(irb.CreateMul(call.getArgOperand(0), call.getArgOperand(1)), Int32Ty); // multiply args to calloc to get total bytes

            // Insert call to dsf_increment(dsf_map, key, bytes);
            irb.CreateCall(DsfIncrementFunction, {DsfMapVariable, key, bytes});
        }
    }
};

FUZZFACTORY_REGISTER_DOMAIN(MemAllocFeedback);
