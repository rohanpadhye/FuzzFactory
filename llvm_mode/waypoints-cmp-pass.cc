#include "fuzzfactory.hpp"

using namespace llvm;

class CmpFeedback : public fuzzfactory::DomainFeedback<CmpFeedback> {

    GlobalVariable* ProgramLocationHash = NULL;
    
    /* Updates a global that tracks the last program location before a wrapcmp_* function is called */
    void updateProgramLocation(IRBuilder<>& irb) {
        irb.CreateStore(createProgramLocation(), ProgramLocationHash);
    }

    /* Construct __wrap_[n]eq<bw> functions on-demand */
    Function* getWrapICmpFunction(bool equal, unsigned bw) {
        StringRef prefix = "__wrap_";
        StringRef eqneq = (equal ? "eq" : "neq");
        std::string fname = (prefix + eqneq + Twine(bw)).str();
        return resolveFunction(fname, getIntTy(1), {getIntTy(bw), getIntTy(bw)});
    }

    /* Return a function __wrap__<name> on-demand */
    Function* getWrapper(Function* cmpFunction) {
        std::string fname = ("__wrap_" + cmpFunction->getName()).str(); // Name is prefix + callee name
        return resolveFunction(fname, cmpFunction->getFunctionType()); // Same type as underlying callee
    }

public:
    CmpFeedback(Module& M) : fuzzfactory::DomainFeedback<CmpFeedback>(M, "__afl_cmp_dsf") { 
        // Create a reference to the global variable "__wrapcmp_program_loc"
        ProgramLocationHash = new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__wrapcmp_program_loc");
    }

    /* Handle icmp instruction */
    void visitICmpInst(ICmpInst& I) {
        // Sanity check
        if (I.getNumOperands() != 2) {
            errs () << "Warning: icmp found with " << I.getNumOperands() << " operands" << "\n";
            return;
        }

        // Ensure that operands of icmp are integers (not vectors)
        Type* operandType = I.getOperand(0)->getType();
        assert(operandType == I.getOperand(1)->getType());

        // Handle '==' and '!='
        bool eq;
        if (I.getPredicate() == ICmpInst::Predicate::ICMP_EQ) {
            eq = true;
        } else if (I.getPredicate() == ICmpInst::Predicate::ICMP_NE) {
            eq = false;
        } else {
            return; // Do not instrument other cmp instructions
        }
        
        IntegerType* intType = dyn_cast<IntegerType>(operandType);
        if (intType == NULL) {
            return; // Only instrument integral comparisons (not structs etc)
        }

        unsigned bw = intType->getBitWidth();
        if (bw != 8 && bw != 16 && bw != 32 && bw != 64) {
            return; // Only instrument 8, 16, 32 and 64 bit comparisons
        }  

        // Set IR irb to point to current instruction
        IRBuilder<> irb = insert_before(I);

        // Set program location hash to a statically generated random value
        updateProgramLocation(irb);

        // Find wrapcmp function
        Function* func = getWrapICmpFunction(eq, bw);
        
        // Wrap cmp
        auto wrap_cmp = irb.CreateCall(func, { I.getOperand(0), I.getOperand(1) });

        // Replace icmp with function call if we created one
        I.replaceAllUsesWith(wrap_cmp);
    }
    
    /* Handle calls to memcmp, strcmp, strncmp, strcasecmp, strncasecmp, strstr */
    void visitCallInst(CallInst& I) {
        Function* callee = I.getCalledFunction();

        // We do not instrument indirect calls
        if (!callee) return;

        // Handle various *cmp functions
        if (callee->getName() == "memcmp" ||
            callee->getName() == "strcmp" ||
            callee->getName() == "strncmp" ||
            callee->getName() == "strcasecmp" ||
            callee->getName() == "strncasecmp" ||
            callee->getName() == "strstr") {

            // Set IR irb to point to current instruction
            IRBuilder<> irb = insert_before(I);

            // Set program location hash to a statically generated random value
            updateProgramLocation(irb);

            // Get arguments
            SmallVector<Value*, 4> args(I.arg_operands());

            // Get wrapper function (e.g. "__wrap_memcmp") that has same signature as callee
            Function* wrapper = getWrapper(callee);

            // Insert a call to the wrapper function
            auto wrap_call = irb.CreateCall(wrapper, args);

            // Replace calls with the result of the wrapper
            I.replaceAllUsesWith(wrap_call);
        }
    }

    /* Handle table switches */
    void visitSwitchInst(SwitchInst& I) {
        Function* WrapSwitchSelect;
        // Get reference to the operand of switch()
        Value* switchOp = I.getCondition();
        
        // Get appropriate wrap switch select function depending on types
        IntegerType* intType = dyn_cast<IntegerType>(I.getCondition()->getType());
        if (intType && intType->getBitWidth() == 32) {
            WrapSwitchSelect = resolveFunction("__wrap_switch_select32", getIntTy(32), {getIntTy(32), getIntTy(32)});
        } else if (intType && intType->getBitWidth() == 64) {
            WrapSwitchSelect = resolveFunction("__wrap_switch_select64", getIntTy(64), {getIntTy(64), getIntTy(32)});
        } else if (intType && intType->getBitWidth() == 16) {
            WrapSwitchSelect = resolveFunction("__wrap_switch_select16", getIntTy(16), {getIntTy(16), getIntTy(32)});
        } else if (intType && intType->getBitWidth() == 8) {
            WrapSwitchSelect = resolveFunction("__wrap_switch_select8",  getIntTy(8),  {getIntTy(8),  getIntTy(32)});
        } else {
            // We do not support other integer types
            return;
        }
        
        // Set IR irb to point to current instruction
        auto irb = insert_before(I);

        // Set program location hash to a statically generated random value
        updateProgramLocation(irb);

        // Create variable-length argument list -- one for each case after the operand and count
        Value** args = new Value*[I.getNumCases() + 2];
        int num_args = 0;
        args[num_args++] = switchOp;
        args[num_args++] = getConst(I.getNumCases());
        for (auto it = I.case_begin(); it != I.case_end(); it++) {
            args[num_args++] = it->getCaseValue();
        }

        CallInst* wrap_call = irb.CreateCall(WrapSwitchSelect, ArrayRef<Value*>(args, num_args));

        // Replace the switch condition with the result of the call
        I.setCondition(wrap_call);

        delete[] args;

    }
};

FUZZFACTORY_REGISTER_DOMAIN(CmpFeedback);
