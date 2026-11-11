/* kdebugprint.h's DPrintf references these globals; keep debug printing off. */
int virtioDebugLevel = 0;
int bDebugPrint = 0;
void (*VirtioDebugPrintProc)(const char *format, ...) = 0;
