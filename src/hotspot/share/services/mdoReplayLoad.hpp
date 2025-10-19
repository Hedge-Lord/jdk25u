/*
 * Load MethodData profiles from a replay file and install into live MDOs.
 */
#ifndef SHARE_SERVICES_MDOREPLAYLOAD_HPP
#define SHARE_SERVICES_MDOREPLAYLOAD_HPP

class JavaThread;

class MDOReplayLoad {
 public:
  static void load(JavaThread* thread);
};

#endif // SHARE_SERVICES_MDOREPLAYLOAD_HPP


