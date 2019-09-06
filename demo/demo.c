#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void* Test(int a, int b) {
  if (a % 3 == 2) { 
    printf("Demo: Reached point A\n");
    if (a > 0x1000) { 
      printf("Demo: Reached point B\n");
      if (b == 0x1001CAFE) { 
        printf("Demo: Reached point C\n");
        if (a == b) { 
          printf("Demo: Reached point D\n");
          abort(); 
        } else {
          printf("Demo: Reached point E\n");
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
