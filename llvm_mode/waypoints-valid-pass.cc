#include "fuzzfactory.hpp"

class ValidFuzzFeedback : public fuzzfactory::DomainFeedback<ValidFuzzFeedback> {
public:
    ValidFuzzFeedback(llvm::Module& M) : fuzzfactory::DomainFeedback<ValidFuzzFeedback>(M, "__afl_valid_dsf") { }

    void visitBasicBlock (llvm::BasicBlock &bb) {
        auto key = createProgramLocation(); // static random value
        
        // Insert call to dsf_increment(dsf_map, key, 1);
        auto irb = insert_before(bb); // Get handle to LLVM IR Builder at this point
        irb.CreateCall(DsfIncrementFunction, {DsfMapVariable, key, getConst(1)}); 
    }
};

FUZZFACTORY_REGISTER_DOMAIN(ValidFuzzFeedback);
