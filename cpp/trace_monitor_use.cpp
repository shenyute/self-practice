#include "trace_monitor.h"
#include <stdio.h>
#include <unistd.h>

int main()
{
  TraceMonitor monitor;
  std::set<int> blockCalls = {2};
  monitor.BlockSysCall(blockCalls);
  monitor.StartTrace();
  printf("child start\n");
  FILE* fp = fopen("oo", "w");
  for (int i = 0; i < 100; i++)
    fprintf(fp, "oo");
  printf("child done\n");
  monitor.EndTrace();
  printf("child end\n");
  sleep(20);
  printf("child sleep end\n");

  return 0;
}
