#ifndef SHARE_SERVICES_PROFILECHECKPOINT_GLOBALS_HPP
#define SHARE_SERVICES_PROFILECHECKPOINT_GLOBALS_HPP

#include "runtime/globals_shared.hpp"

// Defines profile checkpoint (binary MDO) flags. Flags reuse existing names.
#define PROFILECHECKPOINT_FLAGS(develop,                                      \
                                develop_pd,                                   \
                                product,                                      \
                                product_pd,                                   \
                                range,                                        \
                                constraint)                                   \
                                                                               \
  product(ccstr, MDOReplayDumpFile, nullptr, DIAGNOSTIC,                      \
          "File for exporting profiles (binary)")                           \
                                                                               \
  product(ccstr, MDOReplayLoadFile, nullptr, DIAGNOSTIC,                      \
          "File for importing profiles (binary)")                           \
                                                                               \
  product(bool, DumpMDOAtExit, false, DIAGNOSTIC,                             \
          "Dump MDOs to MDOReplayDumpFile at VM exit (binary)")             \
                                                                               \
  product(bool, LoadMDOAtStartup, false, DIAGNOSTIC,                          \
          "Load MDOs from MDOReplayLoadFile at VM startup (binary)")          \
                                                                               \
  product(bool, PrintMDOAtDump, false, DIAGNOSTIC,                            \
          "Debug: print MethodData/MethodCounters for each dumped method")    \
                                                                               \
  product(bool, PrintMDOAfterLoad, false, DIAGNOSTIC,                         \
          "Debug: print MethodData/MethodCounters after loading each method")  \
                                                                               \
  product(bool, EagerCompileAllLoaded, false, DIAGNOSTIC,                      \
          "After loading MDOs at startup, run <clinit> on EagerMainClass "     \
          "if set, then iterate all loaded methods, trigger standard policy "  \
          "transition, and queue compiles; block until compile queues drain")  \
                                                                               \
  product(ccstr, EagerMainClass, nullptr, DIAGNOSTIC,                          \
          "Dotted name of the main class whose <clinit> should be run "        \
          "before eager compilation (e.g., com.example.Main)")

DECLARE_FLAGS(PROFILECHECKPOINT_FLAGS)

#endif // SHARE_SERVICES_PROFILECHECKPOINT_GLOBALS_HPP


