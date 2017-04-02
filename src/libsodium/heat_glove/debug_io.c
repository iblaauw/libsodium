#include <signal.h>
#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#include "debug_io.h"

enum {
    DR7_BREAK_ON_EXEC  = 0,
    DR7_BREAK_ON_WRITE = 1,
    DR7_BREAK_ON_RW    = 3,
};

enum {
    DR7_LEN_1 = 0,
    DR7_LEN_2 = 1,
    DR7_LEN_4 = 3,
};

typedef struct {
    char l0:1;
    char g0:1;
    char l1:1;
    char g1:1;
    char l2:1;
    char g2:1;
    char l3:1;
    char g3:1;
    char le:1;
    char ge:1;
    char pad1:3;
    char gd:1;
    char pad2:2;
    char rw0:2;
    char len0:2;
    char rw1:2;
    char len1:2;
    char rw2:2;
    char len2:2;
    char rw3:2;
    char len3:2;
} dr7_t;


int wr_debug(uint32_t key)
{
    pid_t child;
    pid_t parent = getpid();
    struct sigaction trap_action;
    int child_stat = 0;

    if ((child = fork()) == 0)
    {
        int retval = EXIT_SUCCESS;

        dr7_t dr7 = {0};

        if (ptrace(PTRACE_ATTACH, parent, NULL, NULL))
        {
			printf("could not attach to parent\n");
            exit(EXIT_FAILURE);
        }

		wait(NULL);

		if (ptrace(PTRACE_POKEUSER, parent, offsetof(struct user, u_debugreg[7]), dr7))
        {
			printf("could not poke debug control\n");
            retval = EXIT_FAILURE;
        }
        
		if (ptrace(PTRACE_POKEUSER, parent, offsetof(struct user, u_debugreg[0]), (void*)key))
        {
			printf("could not store key in dr0\n");
            retval = EXIT_FAILURE;
        }
        
		if (ptrace(PTRACE_DETACH, parent, NULL, NULL))
        {
			printf("could not detach from parent\n");
            retval = EXIT_FAILURE;
        }

        exit(retval);
    }

    waitpid(child, &child_stat, 0);
    if (WEXITSTATUS(child_stat))
    {
        printf("child exit !0\n");
        return 1;
    }

    return 0;
}

long rd_debug(void)
{
    pid_t child;
    pid_t parent = getpid();
    struct sigaction trap_action;
    int child_stat = 0;

	long val;

    if ((child = fork()) == 0) // child's code
    {
        int retval = EXIT_SUCCESS;

        if (ptrace(PTRACE_ATTACH, parent, NULL, NULL))
        {
			printf("could not attach to parent\n");
            exit(EXIT_FAILURE);
        }

        //sleep(1);
		wait(NULL);
       
	    // read debug reg into child's val
		val = ptrace(PTRACE_PEEKUSER, parent, offsetof(struct user, u_debugreg[0]), NULL);
       
		// write to parent's val
		if (ptrace(PTRACE_POKEDATA, parent, &val, val))
		{
			printf("could not write to parent's local val\n");
			retval = EXIT_FAILURE;
		}
		if (ptrace(PTRACE_DETACH, parent, NULL, NULL))
        {
			printf("could not detach from parent\n");
            retval = EXIT_FAILURE;
        }

        exit(retval);

		return -1;
    }
	else // parent's code
	{
		waitpid(child, &child_stat, 0);
		if (WEXITSTATUS(child_stat))
		{
			printf("child exit !0\n");
			return 1;
		}
    	
		return val;
	}
}
