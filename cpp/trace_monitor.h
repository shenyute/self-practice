#include <set>
#include <unistd.h>

class TraceMonitor
{
public:
  void BlockSysCall(std::set<int>& syscalls);
  void StartTrace();
  void EndTrace();

private:
  void DoTrace();
  bool WaitForSysCall(pid_t child);
  bool CheckEndTrace();

private:
  pid_t m_child;
  int m_pipefd[2];
  std::set<int> m_blockSyscalls;
};
