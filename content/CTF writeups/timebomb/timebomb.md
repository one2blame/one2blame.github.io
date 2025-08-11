# Commands

docker pull public.ecr.aws/t0j9q6v5/dev/timebomb:v2

dive public.ecr.aws/t0j9q6v5/dev/timebomb:v2

docker run --rm --interactive --tty --entrypoint /bin/bash --volume $(pwd):/tmp public.ecr.aws/t0j9q6v5/dev/timebomb:v2

root@86678b3d7be2:/home/ctf# ls
challenge.c

root@198013c487af:/home/ctf# ls /start.sh
/start.sh

root@198013c487af:/home/ctf# cp /home/ctf/challenge.c /tmp
root@198013c487af:/home/ctf# cp /start.sh /tmp


root@198013c487af:/home/ctf# cat /start.sh

```bash
#!/bin/bash

set -e

echo "[*] Compiling challenge.c..."
gcc /home/ctf/challenge.c -o /home/ctf/challenge \
  -fno-stack-protector -z execstack -no-pie

echo "[*] Deleting challenge.c"
rm /home/ctf/challenge.c

echo "[*] Setting permissions..."
chmod 750 /home/ctf/challenge
chown root:ctf /home/ctf/challenge

echo "[*] Environment:"
echo "    LAMBDA_URL=$LAMBDA_URL"
echo "    SECRET_TOKEN=$SECRET_TOKEN"

echo "Try harder." > /etc/banner_fail

echo "[*] Starting xinetd..."
/usr/sbin/xinetd -dontfork -f /etc/xinetd.conf -filelog /tmp/xinetd.log
```

root@198013c487af:/home/ctf# cat /challenge.c

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

void connection() {
    char *lambda_url = getenv("LAMBDA_URL");
    char *token = getenv("SECRET_TOKEN");

    if (!lambda_url || !token) {
        fprintf(stderr, "[!] Missing environment variables.\n");
        exit(1);  
    }

    printf("[*] Executing Lambda...\n");

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "curl -s -X POST %s -H 'Content-Type: application/json' -d '{\"token\":\"%s\"}'",
             lambda_url, token);

    system(cmd);
    fflush(stdout);
    exit(0);  
}


void timebomb() {
    puts("[----------------------------------------]");
    puts("[  TIMEBOMB TERMINAL: MISSION INTERFACE  ]");
    puts("[----------------------------------------]");
    puts("> DEVICE ARMED: DESTRUCT SEQUENCE INITIATED");
    sleep(1);
    puts("> SECURITY BREACH DETECTED — TRACE PROTOCOL ENGAGED");
    for (int i = 5; i > 0; --i) {
        printf("> SYSTEM WIPE IN: T-minus %d seconds...\n", i);
    fflush(stdout);
    sleep(1);
}
}


void vuln() {
    char buffer[512];
    puts("[-----------------------------------------]");
    puts("[  TIMEBOMB TERMINAL: TERMINAL INTERFACE  ]");
    puts("[-----------------------------------------]");
    puts(" [CLASSIFIED] Authorization required...");
    printf("Enter your OVERRIDE CODE: ");
    fflush(stdout);
    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);
    printf("\n[-] Done.\n");
    fflush(stdout);
    fflush(stdout);
    exit(0);
}



int main() {
    timebomb();
    vuln();

    return 0;
}
```

root@198013c487af:/home/ctf# gcc /home/ctf/challenge.c -o /home/ctf/challenge -fno-stack-protector -z execstack -no-pie -g
/home/ctf/challenge.c: In function 'vuln':
/home/ctf/challenge.c:54:12: warning: format not a string literal and no format arguments [-Wformat-security]
   54 |     printf(buffer);
      |            ^~~~~~
root@198013c487af:/home/ctf# cp /home/ctf/challenge /tmp

# Tools

https://github.com/wagoodman/dive

