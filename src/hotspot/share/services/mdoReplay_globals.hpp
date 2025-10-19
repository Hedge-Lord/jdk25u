#ifndef SHARE_SERVICES_MDOREPLAY_GLOBALS_HPP
#define SHARE_SERVICES_MDOREPLAY_GLOBALS_HPP

#include "runtime/globals_shared.hpp"

// Defines MDO replay/export flags. Only flags here; included via allFlags.hpp.
#define MDOREPLAY_FLAGS(develop,                                             \
                       develop_pd,                                          \
                       product,                                              \
                       product_pd,                                           \
                       range,                                                \
                       constraint)                                           \
                                                                             \
  product(ccstr, MDOReplayDumpFile, nullptr, DIAGNOSTIC,                     \
          "File for exporting profiles")                                    \
                                                                             \
  product(ccstr, MDOReplayLoadFile, nullptr, DIAGNOSTIC,                     \
          "File for importing profiles")                                    \
                                                                             \
  product(bool, DumpMDOAtExit, false, DIAGNOSTIC,                            \
          "Dump MDOs and counters to MDOReplayDumpFile at VM exit")        \
                                                                             \
  product(bool, LoadMDOAtStartup, false, DIAGNOSTIC,                         \
          "Load MDOs and counters from MDOReplayLoadFile at VM startup")   \

DECLARE_FLAGS(MDOREPLAY_FLAGS)

#endif // SHARE_SERVICES_MDOREPLAY_GLOBALS_HPP


