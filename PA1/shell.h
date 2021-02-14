#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
/* "readdir" etc. are defined here. */
#include <dirent.h>
/* limits.h defines "PATH_MAX". */
#include <limits.h>

#define SHELL_BUFFERSIZE 256
#define SHELL_INPUT_DELIM " \t\r\n\a"
#define SHELL_OPT_DELIM "-"

/*
  List of builtin commands, followed by their corresponding functions.
 */
const char *builtin_commands[] = {
    "cd",          // 0: calls shellCD
    "help",        // 1: calls shellHelp
    "exit",        // 2: calls shellExit
    "usage",       // 3: calls shellUsage
    "display",     // 4: calls shellDisplayFile
    "countline",   // 5: calls shellCountline
    "listdir",     // 6: calls shellListDir
    "listdirall",  // 7: calls shellListDirAll
    "find",        // 8: calls shellFind
    "summond",     // 9: calls shellSummond
    "checkdaemon", // 10: calls shellCheckDaemon
    "ls",          // 11: alias for 6 'listdir'
    "l",           // 12: alias for 7 'listdirall'
    "la",          // 13: alias for 7 'listdirall'
    "quit"         // 14: alias for 2 'exit'
};

int numOfBuiltinFunctions()
{
  return sizeof(builtin_commands) / sizeof(char *);
};

/*
The fundamental functions of the shell interface
*/
void shellLoop(void);
char **shellTokenizeInput(char *line);
char *shellReadLine(void);
int shellExecuteInput(char **args);

/*
Functions of the shell interface
*/
int shellCD(char **args);
int shellHelp(char **args);
int shellExit(char **args);
int shellUsage(char **args);
int shellDisplayFile(char **args);
int shellCountLine(char **args);
int shellListDir(char **args);
int shellListDirAll(char **args);
int shellFind(char **args);
int shellSummond(char **args);
int shellCheckDaemon(char **args);

/*This is array of functions, with argument char***/
int (*builtin_commandFunc[])(char **) = {
    &shellCD,          //builtin_commandFunc[0]
    &shellHelp,        //builtin_commandFunc[1]
    &shellExit,        //builtin_commandFunc[2]
    &shellUsage,       //builtin_commandFunc[3]
    &shellDisplayFile, //builtin_commandFunc[4]
    &shellCountLine,   //builtin_commandFunc[5]
    &shellListDir,     //builtin_commandFunc[6]
    &shellListDirAll,  //builtin_commandFunc[7]
    &shellFind,        //builtin_commandFunc[8]
    &shellSummond,     //builtin_commandFunc[9]
    &shellCheckDaemon  //builtin_commandFunc[10]
};
