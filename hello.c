#include <stdio.h>
#include <stdlib.h>

int main(){
        int* ptr = malloc(sizeof(int) * 4);
        printf("mem obj @ %p\n", ptr);
        free(ptr);
        /* use-after-free */
        *ptr = 1;
        
        printf("this should not be reached\n");
        return 0;
}
