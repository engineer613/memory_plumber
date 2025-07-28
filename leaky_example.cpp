#include <stdio.h>
#include <stdlib.h>

void function3() {
    
    int* nums = (int*)malloc(5 * sizeof(int));

    // free(nums); // Uncomment this to run an example with no memory leaks
}

void function2() { function3(); }

void function1() { function2(); }


int main() {
    function1();

    return 0;
}