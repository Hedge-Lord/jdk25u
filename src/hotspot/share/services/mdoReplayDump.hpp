/*
 * Minimal MDO replay dumper helper.
 */
#ifndef SHARE_SERVICES_MDOREPLAYDUMP_HPP
#define SHARE_SERVICES_MDOREPLAYDUMP_HPP

#include "utilities/globalDefinitions.hpp"

class fileStream;

class MDOReplayDump {
 public:
  // Dump ciMethodData-style records for all methods with MDOs
  static void dump_all(fileStream* out);
};

#endif // SHARE_SERVICES_MDOREPLAYDUMP_HPP


