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

#include "utils.h"
#include "randombytes.h"
#include "crypto_secretbox.h"

#include "heat_glove.h"

static int heat_glove_initialized = 0;

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

void _heat_glove_init()
{	
	unsigned long volatile buf;

	// get random pinned register master key
	randombytes_buf(&buf, sizeof buf);
	// set pinned register master key in debug reg 0
	wr_debug(buf);
	// force clear buf to rid of stack variable
	sodium_memzero(&buf, sizeof buf);

	heat_glove_initialized = 1;
}

void
_heat_glove_extend_master(uint8_t* master_ext)
{
	long master;

	// get master key from debug reg
	master = rd_debug();	

	// extend master key to 32 BYTES for secretbox encrypting TODO:use diff alg
	for(int i=0; i < crypto_secretbox_KEYBYTES; i+= sizeof(long))
	{
		memcpy(master_ext+i, &master, sizeof(long));
	}

	// clear master key
	sodium_memzero(&master, sizeof(long));


}

void printb(uint8_t* arr, size_t size) {
	printf("0x");
	for(int i = 0; i < size; i++) {
		printf("%x", arr[i]);
	}
	printf("\n");
}

safekey_t
_heat_glove_encrypt(size_t size, uint8_t* temp_key)
{
	uint8_t* key; // encrypted key to return in safekey_t
	uint8_t* nonce;
	uint8_t master_ext[crypto_secretbox_KEYBYTES];

	key = (uint8_t*) malloc(size + crypto_secretbox_MACBYTES);
	nonce = (uint8_t*) malloc(crypto_secretbox_NONCEBYTES);

	// create a nonce	
	randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

	// get extended master
	_heat_glove_extend_master(master_ext);

	// encrypt key
	_crypto_secretbox_easy(key, temp_key, size, nonce, master_ext);

	// clear master key extended form
	sodium_memzero(master_ext, crypto_secretbox_KEYBYTES);


	safekey_t k = { key, nonce, size };


	return k;

}

int
_heat_glove_decrypt(safekey_t sk, uint8_t* buf)
{
	uint8_t master_ext[crypto_secretbox_KEYBYTES];

	_heat_glove_extend_master(master_ext);

	int ret = _crypto_secretbox_open_easy(buf, sk.key, sk.size + crypto_secretbox_MACBYTES, sk.nonce, master_ext);

	// clear master key extended form
	sodium_memzero(master_ext, crypto_secretbox_KEYBYTES);

	return ret;
}

