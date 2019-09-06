#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Include FuzzFactory API */
#include "waypoints.h"

/* Initialize a DSF key-value map of size 4, with aggregation MAX starting at 0 */
FUZZFACTORY_DSF_NEW(my_dsf, 4, FUZZFACTORY_REDUCER_MAX, 0);

/* Utility for counting ones */
int popcount(uint32_t x) {
  int v = 0;
  while (x != 0) {
    x &= x-1;
    v++;
  }
  return v;
}

void* Test(int a, int b) {
  if (a % 3 == 2) { 
    printf("Demo: Reached point A\n");
    if (a > 0x1000) { 
      printf("Demo: Reached point B\n");
      
      /* Maximize common bits between comparison operands, at key 0 */
      uint32_t comm1 = popcount(~(b ^ 0x1001CAFE)); 
      FUZZFACTORY_DSF_MAX(my_dsf, 0, comm1);

      if (b == 0x1001CAFE) { 
        printf("Demo: Reached point C\n");

        /* Maximize common bits between comparison operands, at key 1 */
        uint32_t comm2 = popcount(~(a ^ b)); 
        FUZZFACTORY_DSF_MAX(my_dsf, 1, comm2);

        if (a == b) { 
          printf("Demo: Reached point D\n");
          abort(); 
        } else {
          printf("Demo: Reached point E\n");

          /* Maximize memory allocation at key 2 */
          FUZZFACTORY_DSF_MAX(my_dsf, 2, a);

          return malloc(a); 
        }
      }
    }
  }
  return NULL;
}

int main(int argc, char** argv) {

  // Read 2 integers from input
  int arr[2];
  fread(arr, sizeof(arr), 2, stdin);
  int a = arr[0];
  int b = arr[1];

  printf("%d, %d\n", a, b);

  void* p = Test(a, b);
  if (p) free(p);

  return 0;
}
