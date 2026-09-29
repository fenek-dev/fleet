/* Stand-in for a team-signed MCP client (e.g. a desktop app): runs its
 * arguments as a child with inherited stdio and waits, so fleetctl's parent
 * is this signed, non-interpreter binary. Build and sign, then pass it as MCP_SIGNED_PARENT to run.py:
 *   cc -O2 -o mcp-parent tests/mcp/parent.c
 *   codesign -s "Apple Development" -i dev.fleet.test.mcp-parent mcp-parent
 */
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s program [args...]\n", argv[0]);
        return 2;
    }
    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid == 0) {
        execvp(argv[1], argv + 1);
        _exit(127);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {}
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
