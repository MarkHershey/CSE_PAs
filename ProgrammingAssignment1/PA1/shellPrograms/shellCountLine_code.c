#include "shellPrograms.h"

/*
Count the number of lines in a file
*/
int shellCountLine_code(char **args)
{

  /** TASK 6  **/
  // ATTENTION: you need to implement this function from scratch and not to utilize other system program to do this
  // 1. Given char** args, open file in READ mode based on the filename given in args[1] using fopen()
  // 2. Check if file exists by ensuring that the FILE* fp returned by fopen() is not NULL
  // 3. Read the file line by line by using getline(&buffer, &size, fp)
  // 4. Loop, as long as getline() does not return -1, keeps reading and increment the count
  // 6. Close the FILE*
  // 7. Print out how many lines are there in this particular filename
  // 8. Return 1, to exit program
  if (args[1] == NULL)
  {
    fprintf(stderr, "Usage: %s filename\n", args[0]);
    return 1;
  }
  FILE *f = fopen(args[1], "r");
  if (f == NULL)
  {
    fprintf(stderr, "Can't open file\n");
    return 1;
  }
  size_t l = 0;
  char *b = NULL;
  int i = 0;

  while (getline(&b, &l, f) + 1)
  {
    ++i;
  }
  printf("There are %d lines in %s\n", i, args[1]);

  return 1;
}

int main(int argc, char **args)
{
  return shellCountLine_code(args);
}
