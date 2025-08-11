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
