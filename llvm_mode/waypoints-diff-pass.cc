#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/IR/DebugInfoMetadata.h"
#include "fuzzfactory.hpp"

using namespace fuzzfactory;
using FileAndLine = std::pair<std::string, int>;

// Target-location parsing borrowed from AFLGo https://github.com/aflgo/aflgo
// Apache License - No copyright notice for this part of the code, but committed by Marcel Böhme
cl::opt<std::string> TargetsFile(
    "target_locations",
    cl::desc("Input file containing the target lines of code."),
    cl::value_desc("target_locations"));

bool loc_description (const DebugLoc& dd, FileAndLine* loc) {
  if (!dd) { return false;}
  auto* scope = cast<DIScope>(dd.getScope());
  std::string full_path = scope->getFilename().str();
  size_t last_slash = full_path.find_last_of("/\\");
  std::string file_name = full_path.substr(last_slash + 1);
  loc->first = file_name;
  loc->second = dd.getLine();
  return true;
}

bool hits_target(const BasicBlock& bb, const std::vector<FileAndLine>& target_locations) {
  FileAndLine instr_loc;
  for (auto& instr: bb.getInstList()) {
      bool has_loc = loc_description(instr.getDebugLoc(), &instr_loc);
      if (has_loc) {
          if (std::find(target_locations.begin(), target_locations.end(), instr_loc) != target_locations.end()) {
              return true;
          }
      }
  } 
  return false;
}

bool populate_target_locations(std::vector<FileAndLine> * target_locations_ptr) {
  /* Get the targeted lines out of the targets file */
  if (TargetsFile.empty()) {
  	std::cerr << "Need to specify -target_locations!\n"; 
    	return false;
  }
  std::ifstream targetsFile(TargetsFile);
  if ( (targetsFile.rdstate() & std::ifstream::failbit ) != 0 ){
	      std::cerr << "Error opening " << TargetsFile << "\n";
	      return false;
  }
  std::string line;
  std::string delimiter = ":";
  while (std::getline(targetsFile, line)){
    size_t colon_pos = line.find(delimiter);
    std::string filename = line.substr(0, colon_pos);
    int line_num = std::stoi(line.substr(colon_pos+1, line.size() - (colon_pos + 1)));
    target_locations_ptr->emplace_back(filename, line_num);
  }
  return true;
}


class IncrementalFuzzingFeedback : public DomainFeedback<IncrementalFuzzingFeedback> {
private:
  GlobalVariable *PrevDiffLoc;
  GlobalVariable *DiffHit;
  GlobalVariable *InMainLoop;
  Function* WaypointHit;
  std::vector<FileAndLine> target_locations;
    


public:
    IncrementalFuzzingFeedback(Module& M) : DomainFeedback<IncrementalFuzzingFeedback>(M, "__afl_diff_dsf") { 

      if (!populate_target_locations(&target_locations)) { 
        errs() << "Could not populate target locations\n";
        return;
      }

      PrevDiffLoc = new GlobalVariable(
          M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_diff_loc");

      DiffHit = new GlobalVariable(
          M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_hits_diff");

      // TODO: this in main loop thing breaks difffuzz for more general applications (that don't have LLVMFuzzerTestOneInput)
      // Make an option or something. 
      InMainLoop = new GlobalVariable(
          M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_in_main_loop");
      
      WaypointHit = Function::Create(FunctionType::get(Type::getVoidTy(C), ArrayRef<Type*>({}), false), GlobalValue::ExternalLinkage, "__afl_print_hits_diff", &M);

    }


    void visitFunction (Function& F) {
        if (target_locations.empty()) {
            return;
        }
          
        bool at_top_of_llvmfuzz = false; 
        if (F.hasName()){
          if (F.getName() == "LLVMFuzzerTestOneInput") {
            at_top_of_llvmfuzz = true;
            for (auto &BB : F) {
              for (auto &I : BB) {
                if (ReturnInst *ri = dyn_cast<ReturnInst>(&I)) {
                  auto irb = insert_before(I);
                  irb.CreateStore(ConstantInt::get(Int32Ty, 0), InMainLoop);
                }
              }
            }
          }
        }

        if (at_top_of_llvmfuzz) {
           BasicBlock::iterator IP = F.begin()->getFirstInsertionPt();
           auto irb = insert_before(*IP);
           irb.CreateStore(getConst(0), DiffHit);
           irb.CreateStore(getConst(1), InMainLoop);
           at_top_of_llvmfuzz = false;
        }
    }

    void visitBasicBlock (BasicBlock &bb) {
        if (target_locations.empty()) {
            return;
        }
        auto irb = insert_before(bb); // Get a handle to the LLVM IR Builder at this point
        
        // Assign hits_diff = 1 if this basic block hits the diff
        if (hits_target(bb, target_locations)) {
           irb.CreateStore(getConst(1), DiffHit);
           irb.CreateCall(WaypointHit, {});
        }

        /* Prepare current and previous locations */
        auto cur_loc = generateRandom31();
        auto CurLoc = getConst(cur_loc);
        auto PrevLoc = irb.CreateLoad(PrevDiffLoc);

        /* Update DSF map */
        auto key = irb.CreateXor(PrevLoc, CurLoc);
        auto value = irb.CreateAnd(irb.CreateLoad(DiffHit), irb.CreateLoad(InMainLoop));
        irb.CreateCall(DsfIncrementFunction, {DsfMapVariable, key, value});

        /* Store (cur_loc >> 1) in prev_loc */
        irb.CreateStore(getConst(cur_loc >> 1), PrevDiffLoc);
    }
};

FUZZFACTORY_REGISTER_DOMAIN(IncrementalFuzzingFeedback);

