#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <stdio.h>
#include <time.h>
int iLogged = 0;
int fLogged = 0;

#pragma warning(disable:4996)

using namespace std;

ofstream ofile;
char dlldirectory[320];

char *GetDirectoryFile(char *filename)
{
static char path[320];
strcpy(path, dlldirectory);
strcat(path, filename);
return path;
}

void __cdecl Writelog(const char *fmt, ...)
{
if(ofile != NULL)
{
if(!fmt) { return; }
va_list va_alist;
char logbuf[256] = {0};
va_start (va_alist, fmt);
_vsnprintf (logbuf+strlen(logbuf), sizeof(logbuf) - strlen(logbuf), fmt, va_alist);
va_end (va_alist);
ofile << logbuf << endl;
}}

void logging(HMODULE hDll){
DisableThreadLibraryCalls(hDll);
GetModuleFileNameA(hDll, dlldirectory, 512);
for(int i = strlen(dlldirectory); i > 0; i--) { if(dlldirectory[i] == '\\') { dlldirectory[i+1] = 0; break; } }
DeleteFileA(GetDirectoryFile("xXRusSXxAddresses.txt"));
ofile.open(GetDirectoryFile("xXRusSXxAddresses.txt"), ios::app);
}


void WriteLogX(LPCSTR szDescription,DWORD dwAddress)
{
	if ( dwAddress )
	{
		Writelog(szDescription,dwAddress);
		iLogged ++;
	}
	else
	{
		Writelog(szDescription,0x00);
		fLogged++;
	}
}





//
//using namespace std;
//
//ofstream ofile;
//char dlldir[320];
//
//char *GoToDirectoryFile(char *filename)
//{
//static char path[320];
//strcpy(path, dlldir);
//strcat(path, filename);
//return path;
//}
//
//char *GetDirectoryFile(char *filename)
//{
//static char path[320];
//strcpy(path, dlldir);
//strcat(path, filename);
//return path;
//}
//void __cdecl AddLog (const char *fmt, ...){
//if(ofile != NULL){
//if(!fmt) { return; }
//va_list va_alist;
//char logbuf[256] = {0};
//va_start (va_alist, fmt);
//_vsnprintf (logbuf+strlen(logbuf), sizeof(logbuf) - strlen(logbuf), fmt, va_alist);
//va_end (va_alist);
//ofile << logbuf << endl;
//}}



DWORD dwSize;
DWORD dwStartAddress;
BOOL bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
for(;*szMask;++szMask,++pData,++bMask)
{
if(*szMask == 'x' && *pData != *bMask)
return 0;
}
return (*szMask)==NULL;
}


