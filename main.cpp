#include "log.h"

DWORD FindPattern(BYTE *bMask, char * szMask, int codeOffset, BOOL extract)
{
	for(DWORD i = 0; i < dwSize; i++)
	{
		if(bCompare((BYTE*)(dwStartAddress + i),bMask,szMask))
		{
			if(extract) 
			{
				return *(DWORD*)(dwStartAddress + i + codeOffset);
			}
			else 
			{
				return (DWORD)(dwStartAddress + i + codeOffset);
			}
		}
	}
	return NULL;
}

void SearchPatterns(void)
{
	Sleep(1000);
	dwStartAddress = 0x400000;
	do 
	{
		dwStartAddress = (DWORD)GetModuleHandleA("warrock.exe");
		Sleep(10);
	}while(!dwStartAddress);
	dwSize = 0x500000;

	struct tm * xTM;
	time_t xTime;
	time (&xTime);
	xTM = localtime(&xTime);

	//======[POINTER]=======//
	DWORD Playerpointer2   = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\x85\xC0\x74\x00\x3B\x88\x00\x00\x00\x00\x75\x00","x????xxx?xx????x?",1,true); 
	DWORD Playerpointer	   = FindPattern((PBYTE)"\x8B\x0D\x00\x00\x00\x00\x33\xC0\x66\x89\x81\xA0\x01\x01\x00\x5E", "xx????xxxxxxxxxx", 2, true);
	DWORD Serverpointer	   = FindPattern((PBYTE)"\x8B\x0D\x00\x00\x00\x00\x3B\x81\x00\x00\x00\x00\x74\x00", "xx????xx????x?", 2, true);
	DWORD dwHealthPointer  = FindPattern((PBYTE)"\x8B\xB0\x00\x00\x00\x00\xE8};", "xx????x", 2, true);
	DWORD dwViewAngels     = FindPattern((PBYTE)"\xA1\x00\x00\x00\x00\xD9\x40\x2C","x???xxxx",1,true);
	DWORD dwdevice = FindPattern((PBYTE)"\x8B\x3D\x00\x00\x00\x00\x51\x50\x68\x00\x00\x00\x00\x6A\x03\x59\xE8\x00\x00\x00\x00\x83\xC4\x0C\x8D\x4D\xD0\xFF\x15\x00\x00\x00\x00\x83\x7B\x2C\x00\x75\x16\x8B\x4D\x08\x8B\x3D\x00\x00\x00\x00\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x59\xEB\x6B\x8B\x43\x34\x8B\xC8\xC1\xE9\x02\xF6\xC1\x01", "xx????xxx????xxxx????xxxxxxxx????xxxxxxxxxxx????x????x????xxxxxxxxxxxxxx",2, true);
	DWORD ofsDevice = FindPattern((PBYTE)"\x8B\x80\x00\x00\x00\x00\x8B\x08\x50\xFF\x91\x00\x00\x00\x00\x33\xC0\x40\xC9\xC3\x55\x8B\xEC\x83\xE4\x00", "xx????xxxxx????xxxxxxxxxx?" , 2, true);

	DWORD dwremotePointer = FindPattern((PBYTE)"\x8B\x3D\x00\x00\x00\x00\x8D\x74\x24\x10\xE8\x00\x00\x00\x00\x8B\x44\x24\x10\x89\x44\x24\x08\x8B\x44\x24\x14\x6A\x20\x8D\x74\x24\x0C","xx????xxx?x????xxxxxxxxxxxxxxxxxx",2,true);

	DWORD GlobalPointer = FindPattern((PBYTE)"\x81\xC3\x00\x00\x00\x00\x3B\x45};","xx????xx",true,2);
	//DWORD dwDevicePointer = FindPattern( (PBYTE)"\xC7\x06\x00\x00\x00\x00\x89\x86\x00\x00\x00\x00\x89\x86};", "xx????xx???xxx",2,true);
	DWORD AngelsPointer = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\xD9\x58\x50\xFF\x15\x00\x00\x00\x00\x99\xF7\xFE\x0F\xBF\x3D\x00\x00\x00\x00","x????xxxxx????xxxxxx????",1,true);
	DWORD StatePointer  = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x33\xDB\x8B\xF0\x38\x1D\x00\x00\x00\x00","x????x????xxxxxx????",1,true);
	DWORD BasePointer   = FindPattern( (PBYTE)"\xBE\x00\x00\x00\x00\xBF\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x03\xF7\x81\xFE\x00\x00\x00\x00","x????x????x????xxxx????",1,true);
	DWORD RoomPointer   = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\x8B\x48\x68\x51\xE8\x00\x00\x00\x00\x8B\xF0\x85\xF6","x????xxxxx????xxxx",1,true);
	DWORD dwUserPointer = FindPattern( (PBYTE)"\x0F\x8C\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00" ,"xx????xx????",8,true);
	DWORD dwUserBase    = FindPattern( (PBYTE)"\x2B\x05\x00\x00\x00\x00\x33\xF6\xC1\xF8\x02", "xx????xxxxx", 2, true);
	DWORD MatrixPointer = FindPattern( (PBYTE)"\x68\x00\x00\x00\x00\x8D\x84\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x6A\x08\xE8\x00\x00\x00\x00","x????xxx????x????xxx????",1,true);
	DWORD dwcBasePointer  = FindPattern( (PBYTE)"\x2B\x05\x00\x00\x00\x00\x33\xF6\xC1\xF8\x02\x89\x1D\x00\x00\x00\x00", "xx????xxxxxxx????", 2, true);

	/*DWORD ptrPlayer = FindPattern( (PBYTE)"\x8B\x0D\x00\x00\x00\x00\x33\xC0\x66\x89\x81\xA0\x01\x01\x00\x5E", "xx????xxxxxxxxxx", true, 2);
	DWORD ptrBase = FindPattern( (PBYTE)"\x81\xC6\x00\x00\x00\x00\x2B\xC2\x66\x89\x8E\xC8\x1B\x00\x00\x33\xC9", "xx????xxxxxxxxxxx", true, 2);*/
	DWORD adrSpeed = FindPattern( (PBYTE)"\xDC\x0D\x00\x00\x00\x00\x59\x59\xD9\x5D\x08\x5E", "xx????xxxxxx", 2, true);
	DWORD ofsInvisible = FindPattern( (PBYTE)"\x8B\x87\x00\x00\x00\x00\x89\x06\x8B\x87\x00\x00\x00\x00\x89\x46\x08", "xx????xxxx????xxx", 2, true);
	DWORD adrD3DUsername = FindPattern( (PBYTE)"\x05\x00\x00\x00\x00\x50\x68\x00\x00\x00\x00\xBF\x00\x00\x00\x00\x57\xFF\x15\x00\x00\x00\x00", "x????xx????x????xxx????", 1, true);
	DWORD adrSpawnTime = FindPattern( (PBYTE)"\x8B\x0D\x00\x00\x00\x00\x69\xC9\x00\x00\x00\x00\x85\xC0", "xx????xx????xx", 2, true);
	DWORD adrFireDelay  = FindPattern( (PBYTE)"\x8D\x86\x00\x00\x00\x00\x50\x51\xD9\x1C\x24\xE8\x00\x00\x00\x00", "xx????xxxxxx????", 2, true);
	DWORD adrUnlimitedAmmo  = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\xFF\x70\x30\x8B\xC6\xE8\x00\x00\x00\x00", "x????xxxxxx????", 1, true);
	DWORD dwLevel         = FindPattern( (LPBYTE)("\x8B\x89\x00\x00\x00\x00\x89\x88"), "xx????xx", 2, true);
	DWORD dwDinar         = dwLevel + 0x10;
	//DWORD dwSlotBase      = FindPattern ( (LPBYTE)("\x8B\x84\x08\x7C\x5F\x0C\x00"),"xxxxxx?",true,3);
	DWORD dwView3D        = FindPattern ( (LPBYTE)("\x66\x89\x87\xA0\x01\x01\x00"),"xxxxxx?",3,true);
	DWORD dwPlayerState   = FindPattern ( (LPBYTE)("\x8B\x8F\xCC\xC4\x00\x00"),"xxxx??",2,true);
	DWORD dwWeaponState   = FindPattern ( (LPBYTE)("\x8B\xB7\xD0\xC4\x00\x00"),"xxxx??",2,true);
	DWORD dwOfsX          = FindPattern ( (LPBYTE)("\x81\xC1\x00\x03\x01\x00"),"xx?xx?",2,true);
	DWORD dwOfsY          = FindPattern ( (LPBYTE)("\x8D\x83\x10\x03\x01\x00"),"xxxxx?",2,true);
	DWORD dwOfsZ          = FindPattern ( (LPBYTE)("\x8D\x83\x08\x03\x01\x00"),"xxxxx?",2,true);
	DWORD dwNoRecoil1     = FindPattern ( (LPBYTE)("\x89\x8E\x44\xC4\x00\x00"),"xxxx??",2,true);
	DWORD dwNoRecoil2     = FindPattern ( (LPBYTE)("\x89\x8E\x48\xC4\x00\x00"),"xxxx??",2,true);
	DWORD dwNoRecoil3     = FindPattern ( (LPBYTE)("\x89\x86\x4C\xC4\x00\x00"),"xxxx??",2,true);
	DWORD dwGravityY      = FindPattern ( (LPBYTE)("\xD9\x87\xB0\xC4\x00\x00"),"xxxx??",2,true);
	DWORD dwGravityX      = dwGravityY + 0x08;
	DWORD dwGravityZ      = dwGravityY + 0x04;
	DWORD dwNoSpread      = FindPattern ( (LPBYTE)("\xD9\x83\x10\x01\x01\x00"),"xxxxx?",2,true);
	//DWORD dwNoReload      = FindPattern ( (LPBYTE)("\x88\x9E\x0D\x04\x01\x00"),"xxxxx?",2,true);
	DWORD dwCommand       = FindPattern ( (LPBYTE)("\xE8\xA2\xA5\x0C\x00"),"xxxx?",5,true);
	DWORD dwCommand2      = FindPattern ( (LPBYTE)("\x6A\x3C"),"xx",0,true);
	DWORD GlobalSizeOffset = FindPattern( (PBYTE)"\x69\xF6\x00\x00\x00\x00\x8B\x82\x00\x00\x00\x00\x3B\x86\x00\x00\x00\x00\x74\x09};","xx????xx????xx????xx",2,true);
	DWORD LocalSizeOffset = FindPattern( (PBYTE)"\x66\x89\xB0\x00\x00\x00\x00\xC3\x83\xC9\xFF\x89\x88\x00\x00\x00\x00\x89\x88\x00\x00\x00\x00\x8B\xD1","xxx????xxxxxx????xx????xx",3,true);
	DWORD dwNoDelay = FindPattern( (PBYTE)"\x8D\x87\x00\x00\x00\x00\x50\x51;}","xx????xx", 2, true );
	DWORD NoReloadOffset = FindPattern( (PBYTE)"\x88\x83\x00\x00\x00\x00\x88\x83\x00\x00\x00\x00\x8A\x47\x01\xC0\xE8\x05\x24\x01","xx????xx????xxxxxxxx",2,true);
	DWORD NoSwitchOffset = FindPattern( (PBYTE)"\x88\x83\x00\x00\x00\x00\x88\x83\x00\x00\x00\x00\x8A\x47\x01\xC0\xE8\x05\x24\x01","xx????xx????xxxxxxxx",2,true);
	DWORD NoRecoil1Offset = FindPattern( (PBYTE)"\x89\x87\x00\x00\x00\x00\x8B\x06\x89\x87\x00\x00\x00\x00\x8B\x46\x04\x89\x87\x00\x00\x00\x00\x5E\xC3","xx????xxxx????xxxxx????xx",2,true);
	DWORD NoRecoil2Offset = FindPattern( (PBYTE)"\x89\x87\x00\x00\x00\x00\x8B\x46\x04\x89\x87\x00\x00\x00\x00\x5E\xC3","xx????xxxxx????xx",2,true);
	DWORD NoRecoil3Offset = FindPattern( (PBYTE)"\x89\x87\x00\x00\x00\x00\x5E\xC3\x55\x8B\xEC","xx????xxxxx",2,true);
	DWORD PositionXOffset = FindPattern( (PBYTE)"\x8D\x87\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xDC\x1D\x00\x00\x00\x00\xDF\xE0\xF6\xC4\x41","xx????x????x????xx????xxxxx",2,true);
	DWORD PositionYOffset = FindPattern( (PBYTE)"\x8D\x83\x00\x00\x00\x00\x8B\x48\x04\x33\x08\x8B\x83\x00\x00\x00\x00\x89\x4C\x24\x14\xD9\x44\x24\x14\xD9\x58\x3C","xx????xxxxxxx????xxxxxxxxxxx",2,true);
	DWORD PositionZOffset = FindPattern( (PBYTE)"\x8D\xB3\x00\x00\x00\x00\xD9\x5D\xF4\xD9\x45\xF4\xD9\x1C\x24\xE8\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xA1\x00\x00\x00\x00","xx????xxxxxxxxxx????x????x????",2,true);
	DWORD NoFallDamageOffset = FindPattern( (PBYTE)"\x8D\xB3\x00\x00\x00\x00\xD9\x1C\x24\x89\xBB\x00\x00\x00\x00\x89\xBB\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00","xx????xxxxx????xx????x????x????",2,true);
	DWORD ViewMainOffset = FindPattern( (PBYTE)"\x8D\x8B\x00\x00\x00\x00\x8B\xC6\xE8\x00\x00\x00\x00\x8B\xC8","xx????xxx????xx",2,true);
	DWORD ViewXOffset = ViewMainOffset+0x0;
	DWORD ViewZOffset = ViewMainOffset+0x4;
	DWORD ViewYOffset = ViewMainOffset+0x8;
	DWORD Slot5Offset = FindPattern ( (LPBYTE)"\xC6\x83\x00\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x8B\x46\x14\x83\xC0\x46\x68\x00\x00\x00\x00\x50\xFF\xD7\x59\x59\x85\xC0","xx?????x????xxxxxxx????xxxxxxx",2,true);
	DWORD Slot6Offset = Slot5Offset+0x1;
	DWORD Slot7Offset = Slot5Offset+0x2;
	DWORD Slot8Offset = Slot5Offset+0x3;
	DWORD PlayerStateOffset = FindPattern( (PBYTE)"\x89\x83\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xF0\x8B\xFB\xE8\x00\x00\x00\x00\x8B\x35\x00\x00\x00\x00","xx????x????xxxxx????xx????",2,true);
	//DWORD MasterOffset = FindPattern( (PBYTE)"\x8B\x86\x00\x00\x00\x00\x89\x86\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x2B\x05\x00\x00\x00\x00\xA9","xx????xx????x????xx????x",2,true);
	DWORD WeaponMainOffset = FindPattern( (PBYTE)"\x66\x8B\x87\x00\x00\x00\x00\x66\x89\x87\x00\x00\x00\x00\x83\xC4\x18\x8B\xC7\xE8\x00\x00\x00\x00","xxx????xxx????xxxxxx????",3,true);
	DWORD Weapon1Offset = WeaponMainOffset+0x0;
	DWORD Weapon2Offset = WeaponMainOffset+0x2;
	DWORD Weapon3Offset = WeaponMainOffset+0x4;
	DWORD UserNameOffset = FindPattern( (PBYTE)"\x8D\x86\x00\x00\x00\x00\xFF\xB6\x00\x00\x00\x00\x8D\x8F\x00\x00\x00\x00\xFF\xB6\x00\x00\x00\x00","xx????xx????xx????xx????",2,true);
	DWORD dwGravZ = FindPattern ( (PBYTE)"\xD9\x9E\x00\x00\x00\x00\x8B\xCE;}", "xx????xx", 2, true);
	DWORD dwGravY = dwGravZ + 0x4;
	DWORD dwGravX = dwGravZ - 0x8;
	DWORD InvisibleOffset = FindPattern( (PBYTE)"\xFF\xB0\x00\x00\x00\x00\x8B\x45\x08\xE8\x00\x00\x00\x00\x8B\x45\x08","xx????xxxx????xxx",2,true);
	DWORD ReadyRoomSize = FindPattern( (PBYTE)"\x8D\x96\x00\x00\x00\x00\x32\xC9\xE8\x00\x00\x00\x00\x8B\x35\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x8B\x78\x0C","xx????xxx????xx????x????x????xxx",2,true);
	DWORD StartRoomSize = FindPattern( (PBYTE)"\x8B\xB0\x00\x00\x00\x00\x83\xC6\x34\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x8B\x80\x00\x00\x00\x00\x83\xF8\x41","xx????xxxx????x????xx????xxx",2,true);
	DWORD LevelOffset = FindPattern( (PBYTE)"\x8B\x89\x00\x00\x00\x00\x89\x88\x00\x00\x00\x00\xC3\x56\xE8\x00\x00\x00\x00\x8B\x70\x14","xx????xx????xxx????xxx",2,true);
	DWORD DinarOffset = FindPattern( (PBYTE)"\x89\x86\x00\x00\x00\x00\x89\x8E\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x50\x8D\x84\x24\x00\x00\x00\x00\x68\x00\x00\x00\x00","xx????xx????xx????xxxx????x????",2,true);
	DWORD SlotBaseOffset = FindPattern( (PBYTE)"\x8D\x84\x08\x00\x00\x00\x00\x50\xE8\x00\x00\x00\x00\x83\xC4\x0C\xE9\x00\x00\x00\x00","xxx????xx????xxxx????",3,true);
	DWORD PitchOffset = FindPattern( (PBYTE)"\xD9\x93\x00\x00\x00\x00\x66\x89\x83\x00\x00\x00\x00\xD9\x93\x00\x00\x00\x00\x88\x83\x00\x00\x00\x00\x33\xC0","xx????xxx????xx????xx????xx",2,true);
	DWORD YawOffset = FindPattern( (PBYTE)"\xD8\xA0\x00\x00\x00\x00\xDC\x35\x00\x00\x00\x00\xDC\x0D\x00\x00\x00\x00\xD9\x5C\x24\x14","xx????xx????xx????xxxx",2,true);
	DWORD PlayerViewOffset = FindPattern( (PBYTE)"\x66\x89\x88\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00\x89\x3D\x00\x00\x00\x00\x3B\xCF","xxx????xx????xx????xx",3,true);
	DWORD PlayerSpeedOffset = FindPattern( (PBYTE)"\xD9\x81\x00\x00\x00\x00\xD8\x45\x08\xD9\x5D\x08\xD9\x45\x08\xDE\xCA","xx????xxxxxxxxxxx",2,true);
	//DWORD dwPremium1 = FindPattern ( (PBYTE)"\x8B\x89\x00\x00\x00\x00\x3B\x48;}", "xx????xx", true, 2);
	//DWORD dwPremium2 = dwPremium1 + 0x4;
	DWORD dwPremium1  = FindPattern((PBYTE)"\x8B\x94\x24\x00\x00\x00\x00\x8B\x8C\x24\x00\x00\x00\x00\x03\xD3\x41\x3B\xCD\x0F\x8C\x00\x00\x00\x00", "xxx????xxx????xxxxxxx????", 3, true);
	DWORD dwPremium2 = FindPattern((PBYTE) "\x8B\x80\x00\x00\x00\x00\xD9\x54\x24\x3C\x48\xD9\x54\x24\x38\xD9\x5C\x24\x34","xx????xxxxxxxxxxxxx",2,true);
	//DWORD dwPremium2 = FindPattern((PBYTE) "\x50\x8D\x84\x24\x00\x00\x00\x00\x50\xFF\x15\x00\x00\x00\x00\x8B\xD8\xE9\x00\x00\x00\x00", "xxxx????xxx????xxx????", 4, true);
	DWORD NoSpreadOffset = FindPattern( (PBYTE)"\xD9\x80\x00\x00\x00\x00\xD9\xE8\xDE\xE1\xD8\x4D\xEC\xD9\x5D\xEC","xx????xxxxxxxxxx",2,true);
	DWORD dwRoomMaster = FindPattern ( (PBYTE)"\x8B\x88\x00\x00\x00\x00\x3B\x88;}", "xx????xx", 2, true);
	
    DWORD mouseIngame = FindPattern ( (PBYTE)"\xA3\x00\x00\x00\x00\x7D\xF0\xEB\x19\x39\x35\x00\x00\x00\x00\x7D\x11\x6A\x01","x????xxxxxx????xxxx",1,true);

	DWORD dwNoReload        = FindPattern((PBYTE)"\xC6\x86\x00\x00\x00\x00\x00\xEB\x34\x38\x5F\x00\x74\x2F","xx?????xxxx?xx",2,true);
	DWORD dwWeaponDamage    = FindPattern((PBYTE)"\x39\x86\x00\x00\x00\x00\x5E\x0F\x9F\xC0\xC3\x55\x8B\xEC","xx????xxxxxxxx",2,true);
	DWORD dwWeaponDefence   = FindPattern((PBYTE)"\x8B\x8B\x00\x00\x00\x00\x83\xC4\x00","xx????xx?",2,true);
	DWORD dwWeaponRange     = FindPattern((PBYTE)"\x8B\x8E\x00\x00\x00\x00\xEB\x03\x6A\x14","xx????xxxx",2,true);
	DWORD dwAmmoNumber      = FindPattern((PBYTE)"\x8B\x82\x00\x00\x00\x00","xx????",2,true);
	DWORD dwMagazineNumber  = FindPattern((PBYTE)"\x8B\x9A\x00\x00\x00\x00","xx????",2,true);
	DWORD dwEffectRange     = FindPattern((PBYTE)"\xDB\x80\x00\x00\x00\x00\x51","xx????x",2,true);
	DWORD dwParabola        = dwEffectRange + 0x4;
	DWORD dwShotSpeed       = FindPattern((PBYTE)"\x8B\x86\x00\x00\x00\x00\x3B\x81\x00\x00\x00\x00\x75\x3C","xx????xx????xx",2,true);
	DWORD dwWeaponWheight   = FindPattern((PBYTE)"\x8B\x86\x00\x00\x00\x00\x3B\x81\x00\x00\x00\x00\x75\x2E","xx????xx????xx",2,true);

	
	
	
	//======[Addresses]=======//
	DWORD dwNoSpawnWait1   = FindPattern ( ( PBYTE ) "\x8B\x0D\x00\x00\x00\x00\x69\xC9\x00\x00\x00\x00\x85\xC0\x8B\x07\x74\x00" , "xx????xx????xxxxx?" , 2 , true ) ;
	DWORD dwNoSpawnWait2 = dwNoSpawnWait1 + 0x4;
	DWORD dwNoSpawnWait3 = dwNoSpawnWait1 + 0x8;

	DWORD NoBounds1 = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\x33\x05\x00\x00\x00\x00\x7E\x00\xD9\x05\x00\x00\x00\x00\xD9\x1D\x00\x00\x00\x00\x6A\x00" , "x????xx????x?xx????xx????x?" , 1 , true ) ;
	DWORD NoBounds2 = NoBounds1 + 0x4;
	DWORD NoBounds3 = NoBounds2 + 0x4;

	DWORD NoWaterMemory1 = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\x33\x05\x00\x00\x00\x00\x8B\x97\x00\x00\x00\x00\x8B\xB7\x00\x00\x00\x00","x????xx????xx????xx????",1,true);
	DWORD NoWaterMemory2 = FindPattern( (PBYTE)"\x33\x05\x00\x00\x00\x00\x8B\x97\x00\x00\x00\x00\x8B\xB7\x00\x00\x00\x00\x8B\x8F\x00\x00\x00\x00","xx????xx????xx????xx????",2,true);
	DWORD WalkThroughWallsMemory = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\xD9\x1C\x24\x6A\x00\xE8\x00\x00\x00\x00\x83\xC4\x18\xE8\x00\x00\x00\x00","xx????xxxxxx????xxxx????",2,true);
	DWORD FastLockOnMemory = FindPattern( (PBYTE)"\xD8\x05\x00\x00\x00\x00\xD9\x1D\x00\x00\x00\x00\xD9\x05\x00\x00\x00\x00\xD8\x1D\x00\x00\x00\x00","xx????xx????xx????xx????",2,true);
	DWORD SuperNoSpreadMemory = FindPattern( (PBYTE)"\xDD\x05\x00\x00\x00\x00\x6A\xFF\xFF\x35\x00\x00\x00\x00\xDC\xC1\xD9\xC9\x8B\xCF","xx????xxxx????xxxxxx",2,true);
	DWORD PlantAnyWhereMemory = FindPattern( (PBYTE)"\x38\x1D\x00\x00\x00\x00\x74\x1C\x66\x39\x1D\x00\x00\x00\x00\x7C\x13\x8B\xBF\x00\x00\x00\x00\xE8\x00\x00\x00\x00","xx????xxxxx????xxxx????x????",2,true);
	DWORD DefuseAnyWhereMemory = FindPattern( (PBYTE)"\x0F\xBF\x35\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x00\xD9\xEE\xD9\x58\x18","xxx????x????xxxxxxx",3,true);
	DWORD AutoRepairMemory = FindPattern( (PBYTE)"\xC6\x05\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x57\xC6\x05\x00\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00","xx????xx????xxx????xxx????",2,true);
	DWORD ScopeMemory = FindPattern( (PBYTE)"\xA3\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x50\xE8\x00\x00\x00\x00\x3C\x01","x????x????xx????xx",1,true);
	DWORD Artilery		= FindPattern( (PBYTE)"\xDD\x05\x00\x00\x00\x00\xD9\xC0","xx????xx",2,true);
	DWORD FastHealthMemory = FindPattern( (PBYTE)"\xBE\x00\x00\x00\x00\xD9\x1C\x24\xC6\x05\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x33\xC0\x40","x????xxxxx????xx????xxx",1,true);
	DWORD FastAmmoMemory = FindPattern( (PBYTE)"\xBE\x00\x00\x00\x00\xC6\x05\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x57\xC6\x05\x00\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x59","x????xx????xx????xxx????xxx????x",1,true);
	DWORD FastFlagMemory = FindPattern( (PBYTE)"\xBE\x00\x00\x00\x00\x66\xA3\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xD9\xEE\x51","x????xx????x????xxx",1,true);
	DWORD dwWUW = FindPattern( (PBYTE)"\x33\x05\x00\x00\x00\x00\x89\x45\xFC\xD9\x45\xFC\xA1\x00\x00\x00", "xx???xxxxxxxx???", 2, true );
	DWORD UnlAmmoMemory = FindPattern( (PBYTE)"\x83\x25\x00\x00\x00\x00\x00\xC3\xD9\xEE\xC7\x00\x00\x00\x00\x00\xD9\x50\x0C","xx????xxxxxx????xxx",2,true);
	DWORD dwBoneShot = FindPattern( (PBYTE)"\xDC\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00","xx???xx???x",2,true);
	DWORD dwSTW = FindPattern( (PBYTE)"\xD8\x1D\x00\x00\x00\x00\xDF\xE0\xF6\xC4\x00\x7A\x02","xx???xxxxx?xx",2,true);
	DWORD dwSpeed = FindPattern( (PBYTE)"\xDC\x0D\x00\x00\x00\x00\x59\x59","xx????xx",2,true);
	DWORD dwDeathCam = FindPattern( (PBYTE)"\xF6\x05\x00\x00\x00\x00\x00\x75\x00", "xx???x?x?", 2, true);
	DWORD dwImmExplosion = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\xD8\x1D\x00\x00\x00\x00\xDF\xE0", "xx???xxx???xxx", 2, true);
	DWORD dwPlayerProne = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\x85\xC0\x75\x00", "x???xxxx?", 1, true); 
	DWORD dwStaminaRefill = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\x51\x51\x8B\xC4", "xx???xxxxx", 2, true);
	DWORD dwAntiRadar = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\xD9\xC0\xDE\xEA\xD9\xC9\xD9\x5D\x00\xD9\x45\x00\xDE\xCA\xDE\xC1\xD9\x5D\x00\xD9\x05\x00\x00\x00\x00", "xx???xxxxxxxxx?xx?xxxxxx?xx???x", 2, true);
	DWORD dwQuickPlant = FindPattern( (PBYTE)"\xD9\x1D\x00\x00\x00\x00\xE8\x00\x00\x00\x00", "xx???xx??xx", 2, true);
	DWORD dwBigCarName = FindPattern( (PBYTE)"\xDD\x05\x00\x00\x00\x00\xEB\x00\xD9\xEE\xD9\x5D\x00", "xx???xx?xxxx?", 2, true);
	DWORD dwWeaponShot1 = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\x85\xC0\x75\x00\x6A\x00\xE8\x00\x00\x00\x00};", "x???xxxx?x?x???x", 1, true);
	DWORD dwWeaponShot2 = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\x85\xC0\x75\x00\x6A\x00\xE8\x00\x00\x00\x00\x59\x85\xC0\x74\x00\x6A\x00\x59\xC7\x00\x00\x00\x00\x00\x66\x89\x48\x00\xEB\x00\x33\xC0\xA3\x00\x00\x00\x00\xC3\x55", "x???xxxx?x?x???xxxxx?x?xxx???xxxx?x?xxx???xxx", 1, true);
	DWORD dwBreaklimit = FindPattern( (PBYTE)"\xDD\x00\x00\x00\x00\x00\xD8\xD1\xDF\xE0\xDD\xD9\xF6\xC4\x00};", "x?????xxxxxxxx?", 2, true);
	DWORD dwFullBright  = FindPattern( (PBYTE)"\xD8\x05\x00\x00\x00\x00\xDE\xE1\xD8\x45\xE0", "xx????xxxxx", 2, true);
	DWORD dwFullBright2  = (dwFullBright+0x4);
	DWORD dwFullBright3  = (dwFullBright2+0x4);
	DWORD dwGlassWall  = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\xD9\x5C\x24\x0C\xD9\xEE", "xx????xxxxxx", 2, true);
	DWORD dwWeaponGravity = FindPattern( (PBYTE)"\xDC\x3D\x00\x00\x00\x00\xDE\xF9\xD8\xF2\xD9\x5F\x2A\xD9\x86\x00\x00\x00\x00", "xx????xxxxxxxxx????", 2, true);
	DWORD dwSilentWalk  = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\x85\xC0\x75\x23\x6A\x30", "x????xxxxxx", 1, true);
	DWORD dwLadderQuickly = FindPattern( (PBYTE)"\xDC\x0D\x00\x00\x00\x00\x83\xEC\x14\xD9\xEE", "xx????xxxxx", 2, true);
	DWORD dwCrossHair  = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\x99\x2B\xC2\xD1\xF8\x39\x05\x00\x00\x00\x00\xBE\x00\x00\x00\x00", "x????xxxxxxx????x????", 1, true);
	DWORD dwColorShot = FindPattern( (PBYTE)"\xD8\x05\x00\x00\x00\x00\xDE\xE1\xD8\x45\xE0\xD9\x5D\xF4\xD9\x45\xF4\xD9\x5D\xEC", "xx????xxxxxxxxxxxxxx", 2, true);
	DWORD dwDeadSpinner = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\x83\xC4\x10\x6A\x00\x6A\x00\x51\xD9\x1C\x24\x50\x8B\xF7\xE8\x00\x00\x00\x00", "xx????xxxxxxxxxxxxxxx????", 2, true);
	DWORD dwHideWeapon = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\x51\xD9\x1C\x24", "xx????xxxx", 2, true);
	DWORD dwChangeRoll = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\xD9\x1C\x24\x68\x00\x00\x00\x00", "xx????xxxx????", 2, true);
	DWORD dwWTH = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\x83\xC4\x00", "xx???xxx?", 2, true);
	DWORD dwRollSpeed  = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\xD9\x5D\xFC\x52\xE8\x00\x00\x00\x00", "xx????xxxxx????", 2, true);
	DWORD dwVirtualJump  = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\xC3\xD9};" ,"xx???xxx",2,true);
	DWORD dwImDrunk   = FindPattern( (PBYTE)"\x66\x83\x3D\x00\x00\x00\x00\x00\x00\x74\x00\x8B\x00\x00\x00};", "xxx??????x?x???",3,true);
	DWORD dwSniperAmmo = FindPattern ( (PBYTE)"\x88\x1D\x00\x00\x00\x00\x38\x1D", "xx????xx", 2, true);
	DWORD dwExtraAmmo1 = dwSniperAmmo - 0x2;
	DWORD dwExtraAmmo2 = dwSniperAmmo - 0x1;
	DWORD dwAssaultAmmo = dwSniperAmmo + 0x2;
	DWORD dwBandage = dwSniperAmmo + 0x4;

	DWORD dwClanTag1        = FindPattern((PBYTE)"\x83\x25\x00\x00\x00\x00\x00\xA3\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x8D\x73\x00","xx?????x????x????xx?",2,true);
	DWORD dwClanTag2        = FindPattern((PBYTE)"\xA3\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x8D\x73\x00","x????x????xx?",1,true);
	DWORD dwClanTag3        = FindPattern((PBYTE)"\xA3\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x56\x68\x00\x00\x00\x00","x????x????xx????",1,true);
	DWORD dwClanTag4        = FindPattern((PBYTE)"\x68\x00\x00\x00\x00\x50\x03\xCF","x????xxx",1,true);
	DWORD dwClanTag5        = FindPattern((PBYTE)"\xC6\x05\x00\x00\x00\x00\x00\x85\xC0\x7E\x2F","xx?????xxxx",2,true);
	DWORD dwClanTag6        = FindPattern((PBYTE)"\x8D\xB6\x00\x00\x00\x00\x50\x8B\xCE","xx????xxx",2,true);
    DWORD RoomMaster = FindPattern( (PBYTE)"\xFF\xB0\x00\x00\x00\x00\xFF\x75\x00\xE8\x00\x00\x00\x00\x8B\x45\x00\x83\xC4\x00\xC9\xC3", "xx????xx?x????xx?xx?xx",2,true);
    DWORD Swim1 = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\x85\xC0\x75\x00\x56\x6A\x00\xE8\x00\x00\x00\x00\x8B\xF0\x59\x85\xF6","x????xxx?xx?x????xxxxx",1,true);
	DWORD Swim2 = FindPattern( (PBYTE)"\x8B\x0D\x00\x00\x00\x00\x56\x57\x33\xFF\x33\xF6\x47\x3B\xCE\x74\x00\x8B\x01\x57\xFF\x90\x00\x00\x00\x00","xx????xxxxxxxxxx?xxxxx????",2,true);
	DWORD cqcProne = FindPattern( (PBYTE)"\xD9\x05\x00\x00\x00\x00\xD8\xD1\xDF\xE0\xF6\xC4\x00\x0F\x8A\x00\x00\x00\x00\xD8\xD1\xDF\xE0\xF6\xC4\x00\x7B\x00\xDD\xD9","xx????xxxxxx?xx????xxxxxx?x?xx",2,true);
	DWORD KickMessage2 = FindPattern( (PBYTE)"\xE8\x00\x00\x00\x00\x59\x8D\x4D\x00\xE9\x00\x00\x00\x00\x8D\x45\x00\x50\xB9\x00\x00\x00\x00\xE8\x00\x00\x00\x00","x????xxx?x????xx?xx????x????",1,true);
	//DWORD gamemode         = cqcProne + 0x8;
	DWORD packet = FindPattern ( (PBYTE)"\x81\xC6\x00\x00\x00\x00\x56\x8B\xCF\xE8\x00\x00\x00\x00\x57\xFF\x15\x00\x00\x00\x00\x59\x5F\x5E\x5B\xC9\xC3", "xx????xxxx????xxx????xxxxxx", 2, true);
	DWORD gamemode         = FindPattern( (PBYTE)"\x83\x3D\x00\x00\x00\x00\x00\x74\x3C\x56\x8B\x35\x00\x00\x00\x00\x8B\x46\x10\x2B\x46\x0C\x33\xD2\xC1\xF8\x02\x85\xC0\x76\x25\x8B\xC6\xE8\x00\x00\x00\x00\x85\xC0","xx?????xxxxx????xxxxxxxxxxxxxxxxxx????xx",2,true);
	//======[WeaponBinder]=======//
	DWORD dwClassBase  = FindPattern( (PBYTE)"\x8B\x80\x00\x00\x00\x00\x8D\x4D\x00\x51\xFF\x75\x00", "xx???xxx?xxx?", 2, true);
	DWORD dwWeaponBase  = FindPattern( (PBYTE)"\xA1\x00\x00\x00\x00\x8B\x04\xB8\x6A\x00\x83\xC0\x00", "x???xxxxx?xx?", 1, true);
	//======[AntiAbnormal]=======//
	DWORD AntiAbnormal1  = FindPattern( (PBYTE)"\x89\x88\x00\x00\x00\x00\x51\x05\x00\x00\x00\x00\x50\xE8\x00\x00\x00\x00\x83\xC4\x00\xC3", "xx????xx????xx????xx?x", 2, true);
	DWORD AntiAbnormal2  = AntiAbnormal1 + 0x1; 
	DWORD AntiAbnormal3  = FindPattern( (PBYTE)"\x89\x88\x00\x00\x00\x00\x89\x88\x00\x00\x00\x00\x89\x88\x00\x00\x00\x00\xC3\x8B\x46\x00\x57\x33\xFF\x89\xBE\x00\x00\x00\x00", "xx????xx????xx????xxx?xxxxx????", 2, true);
	DWORD AntiAbnormal4  = AntiAbnormal3 + 0x1; 
	//======[User]=======//
	DWORD HealthUserInfo = FindPattern( (PBYTE)"\x89\xBE\x00\x00\x00\x00\x89\xBE\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x83\x7B\x18\x10","xx????xx????x????xxxx",2,true);
	DWORD NameUserInfo = FindPattern( (PBYTE)"\x81\xC6\x00\x00\x00\x00\x56\xE8\x00\x00\x00\x00\x59\x59\x5E\x5B\xC3","xx????xx????xxxxx",2,true);
	DWORD PointsUserInfo = FindPattern( (PBYTE)"\xB8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x85\x00\x00\x00\x00\x53","x????x????x????xxxx????x",1,true);
	DWORD PingUserInfo = FindPattern( (PBYTE)"\x8B\x83\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x83\xBB\x00\x00\x00\x00\x00","xx????x????xx????x",2,true);

	//======[ ASM ]=======//
	DWORD dwQuickDefuseASM = FindPattern( (PBYTE)"\x7D\x00\x53\xB8\x00\x00\x00\x00\x50\x50\x53\xFF\x15\x00\x00\x00", "x?xx???xxxxxx???", 0, 0);
	DWORD dwBullets = FindPattern( (PBYTE)"\x0F\xB7\x85\x00\x00\x00\x00\xD9\xE8\x83\xA5\x00\x00\x00\x00", "xxx????xxxx????", 0, 0);
	DWORD dwWTWASM = FindPattern( (PBYTE)"\x0C\x00\xC1\xD8\x00\x34\x00\x5C\x24\x00\xD9\x44\x24\x00\xD8\xD1", "x?xx?x?xx?xxx?xx", 0, 0);
	DWORD dwSTWASM = FindPattern( (PBYTE)"\x8B\x47\x00\x83\xC4\x00\x5F\x5E\x83\xC4\x00\xC3\x8B\xC7\x8B\xCE", "xx?xx?xxxx?xxxxx", 0, 0);
	DWORD dwBacktolobby = FindPattern( (PBYTE)"\x8B\x40\x00\x56\xFF\x74\x24\x00\x8B\xB0\x00\x00\x00\x00\xFF\x74", "xx?xxxx?xx??xxxx", 0, 0);
	DWORD dwAlwaysCrossAsm = FindPattern( (PBYTE)"\x74\x00\xD9\xC9\x8D\x45\x00\xD9\x55\x00\x89\x7D\x00\xD9\x5D\x00", "x?xxxx?xx?xx?xx?", 0, 0);
	DWORD dwEngineText   = FindPattern((PBYTE)"\x6A\x00\xB8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x5D\x00\x33\xF6\x66\x39\x35\x00\x00\x00\x00\x74\x00\x39\x75\x00","x?x????x????xx?xxxxx????x?xx?",0,0);
	DWORD dwMessageBox = FindPattern( (PBYTE)"\x33\xC0\x50\x68\x00\x00\x00\x00", "xxxx???x", 0, 0);
	DWORD dwUnlAmmo = FindPattern( (PBYTE)"\x56\x8B\xF0\x83\xBE\x00\x00\x00\x00\x00\x74\x00", "xxxxx??xxxx?", 0, 0);
	DWORD dwSwitchTime = FindPattern( (PBYTE)"\x74\x00\xFF\x36\xE8\x00\x00\x00\x00", "x?xxx????", 0, 0);
	DWORD dwOPKAsm = FindPattern( (PBYTE)"\x55\x8B\xEC\x51\x51\x8B\x00\x14\x33\x00\x10", "xxxxxx?xx?x", 0, 0 );
	DWORD dwAUTOStart = FindPattern( (PBYTE)"\x6A\x3C\xB8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xDB\x3B\xC3\x0F\x84\x00\x00\x00\x00\x8B\x88\x00\x00\x00\x00\x3B\x88\x00\x00\x00\x00\x0F\x85\x00\x00\x00\x00\x8B\x80\x00\x00\x00\x00\x89\x45\x08\x8D\x45\x08\x50", "xxx????x????x????xxxxxx????xx????xx????xx????xx????xxxxxxx", 0, 0);
	DWORD dwSuperCarSound = FindPattern( (PBYTE)"\x8B\x80\x00\x00\x00\x00\x33\xFF\x57\x57\x50\xE8\x00\x00\x00\x00", "xx??xxxxxxxx????", 0, 0);
	DWORD Damage = FindPattern((PBYTE)"\x0F\xBF\x83\xEE\x01\x01\x00;}", "xxxxxxx",  0, 0);
	DWORD vehicleJump1 = FindPattern((PBYTE)"\x75\x00\x38\x99\x00\x00\x00\x00\x74\x00\x5E\x5B\xE9\x00\x00\x00\x00\x5E", "x?xx????x?xxx????x", 0, 0);//+0x8 = vehJump2
	DWORD vehicleJump2 = FindPattern((PBYTE)"\x74\x00\x5E\x5B\xE9\x00\x00\x00\x00\x5E\x5B\xC3\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00", "x?xxx????xxxxxxxx????x????", 0, 0);
	DWORD vehicleNoDamage = FindPattern((PBYTE)"\x6A\x00\xB8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x55\x00\xA1\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x89\x45\x00\x85\xC0", "x?x????x????xx?x????x????xx?xx", 0, 0);
	DWORD SuperCar1 = FindPattern( (PBYTE)"\x74\x00\xA1\x00\x00\x00\x00\x33\x05\x00\x00\x00\x00\x89\x45\x00\xA1\x00\x00\x00\x00\xD9\x45\x00\x33\x05\x00\x00\x00\x00","x?x????xx????xx?x????xx?xx????",0,0); 
	DWORD SuperCar2 = FindPattern( (PBYTE)"\x7A\x00\xD9\xEE\x51\xBE\x00\x00\x00\x00\xD9\x1C\x24\xE8\x00\x00\x00\x00\x8B\x45\x00\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00","x?xxxx????xxxx????xx?x????x????",0,0);
	DWORD SuperCar3 = FindPattern( (PBYTE)"\x33\xFF\x57\x57\x50\xE8\x00\x00\x00\x00\xEB\x00\x33\xFF\x39\x7D\x00\x0F\x85\x00\x00\x00\x00","xxxxxx????x?xxxx?xx????",0,0);
	DWORD STW1 = FindPattern( (PBYTE)"\xD9\x41\x00\xD9\x58\x00\xD9\x41\x00\xD9\x58\x00\xC3\xCC\xCC\xCC\xD9\xEE","xx?xx?xx?xx?xxxxxx",0,0);//+0x6 = stw2
	DWORD STW2 = FindPattern( (PBYTE)"\xD9\x41\x00\xD9\x58\x00\xC3\xCC\xCC\xCC\xD9\xEE","xx?xx?xxxxxx",0,0);
	//DWORD stw2 = FindPattern((PBYTE)"\xD9\x41\x00\xD9\x58\x00\xC3\xCC\xCC\xCC\xD9\xEE\xD9\x50\x00","xx?xx?xxxxxxxx?",0,0);
	DWORD EventRoom = FindPattern( (PBYTE)"\x74\x00\x83\x3D\x00\x00\x00\x00","x?xx????",0,0);
	DWORD EventRoom2 = FindPattern( (PBYTE)"\x74\x00\xE8\x00\x00\x00\x00\xB1\x00\xEB\x00\xE8\x00\x00\x00\x00\x32\xC9","x?x????x?x?x????xx", 0,0);
	DWORD AiKniferoom = FindPattern( (PBYTE)"\x74\x00\x8D\x45\x00\x50\xB9\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x59","x?xx?xx????x????x",0,0);
	DWORD UnlOxygen = FindPattern( (PBYTE)"\x75\x00\xD9\x45\x00\xDC\x05\x00\x00\x00\x00\xD9\x45\x00\xDC\x05\x00\x00\x00\x00\xDE\xD9\xDF\xE0","x?xx?xx????xx?xx????xxxx",0,0);
	DWORD artillery0 = FindPattern( (PBYTE)"\x75\x00\x83\xFE\x00\x74\x00\x3B\xF3\x0F\x85\x00\x00\x00\x00\x83\xF9\x00","x?xx?x?xxxx????xx?",0,0);
	DWORD artillery1 = FindPattern( (PBYTE)"\x75\x00\x40\x3B\xF0\x0F\x84\x00\x00\x00\x00\x3B\xF3\x0F\x85\x00\x00\x00\x00","x?xxxxx????xxxx????",0,0);
	DWORD artillery2 = FindPattern( (PBYTE)"\x75\x00\x8D\x44\x24\x00\x50\xB9\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x59\xC7\x44\x24\x00\x00","x?xxx?xx????x????xxxx??",0,0);
	DWORD artillery3 = FindPattern( (PBYTE)"\x7D\x00\x8D\x44\x24\x00\x50\xB9\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x59\xC7\x44\x24\x00","x?xxx?xx????x????xxxx?",0,0);
	DWORD artillery4 = FindPattern( (PBYTE)"\x74\x00\x46\x83\xFE\x00\x7C\x00\x8D\x45\x00\x50\xB9\x00\x00\x00\x00\xE8\x00\x00\x00\x00","x?xxx?x?xx?xx????x????",0,0);
	DWORD artillery5 = FindPattern( (PBYTE)"\xE9\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xC6\x80\x00\x00\x00\x00","x????x????xx????",0,0);
	DWORD artillery6 = FindPattern( (PBYTE)"\x7A\x00\x8D\x44\x24\x00\x50\xB9\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x59","x?xxx?xx????x????x",0,0);
	DWORD artillery7 = FindPattern( (PBYTE)"\x0F\x85\x00\x00\x00\x00\x33\x06\x40\x50\xE8\x00\x00\x00\x00\x8D\x44\x24\x00\x50","xx????xxxxx????xxx?x",0,0);
	///*falls zukurz*/DWORD artillery5 = FindPattern( (PBYTE)"\xE9\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xC6\x80\x00\x00\x00\x00\x8B\x7B\x00\x33\xC0\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xB8\x00\x00\x00\x00","x????x????xx????xx?xxx????x????x????xx????",0,0);
	DWORD userKill = FindPattern( (PBYTE)"\xD9\x58\x00\xDB\x45\x00\xD9\x58\x00\xA1\x00\x00\x00\x00\x33\x05\x00\x00\x00\x00\x89\x45\x00\x8B\x03","xx?xx?xx?x????xx????xx?xx",0,0);
	DWORD fakeKick = FindPattern( (PBYTE)"\x8B\xCE\x89\x46\x00\xE8\x00\x00\x00\x00\x56\xFF\x15\x00\x00\x00\x00\x59\xE8\x00\x00\x00\x00\xC3","xxxx?x????xxx????xx????x",0,0);
	DWORD spamBot  = FindPattern( (PBYTE)"\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x8B\x45\x00\x53\x33\xDB","xxxxx????x????xxxx?xx?xxx",0,0);
	DWORD opk1  = FindPattern( (PBYTE)"\x33\x51\x00\x89\x55\x00\x8B\x51\x00\x33\x51\x00\x89\x55\x00","xx?xx?xx?xx?xx?",0,0);
	DWORD opk2 = FindPattern((PBYTE)"\x33\x51\x00\x89\x55\x00\x8B\x51\x00\xD9\x45\x00\x33\x11\xD9\x58\x00\xD9\x45\x00","xx?xx?xx?xx?xxxx?xx?",0,0);
	DWORD opk3 = FindPattern((PBYTE)"\x33\x11\xD9\x58\x00\xD9\x45\x00\xD9\x58\x00\x89\x10\xC9\xC3","xxxx?xx?xx?xxxx",0,0);
	DWORD antioverheat = FindPattern((PBYTE)"\x33\x44\x24\x00\x89\x06\x8B\x57\x00\x33\xD0\x89\x54\x24\x00\xD8\x54\x24\x00\xDF\xE0","xxx?xxxx?xxxxx?xxx?xx",0,0);
	DWORD autorepair1 = FindPattern((PBYTE)"\x0F\x84\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\x05\x00\x00\x00\x00\x89\x45\x00\xA1\x00\x00\x00\x00\xD9\x45\x00\x33\x05\x00\x00\x00\x00","xx????x????xx????xx?x????xx?xx????",0,0);
	DWORD autorepair2 = FindPattern((PBYTE)"\x0F\x8A\x00\x00\x00\x00\x39\x3D\x00\x00\x00\x00\x74\x00\x8B\x45\x00\x8B\x80\x00\x00\x00\x00\x6A\x00\x50","xx????xx????x?xx?xx????x?x",0,0);
	DWORD autorepair3 = FindPattern((PBYTE)"\x57\x57\xFF\xB0\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xEB\x00\xD9\xEE\x51","xxxx????x????x?xx?",0,0);
	DWORD autoammo1 = FindPattern((PBYTE)"\x75\x00\xD9\xEE\x51\xBE\x00\x00\x00\x00\xD9\x1C\x24\xE8\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xA1\x00\x00\x00\x00","x?xxxx????xxxx????x????x????",0,0);
    DWORD autoammo2 = FindPattern((PBYTE)"\x0F\x8A\x00\x00\x00\x00\xD9\xEE\x51\xBE\x00\x00\x00\x00\xD9\x1C\x24\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xD9\xEE","xx????xxxx????xxxx????x????xx",0,0);
	DWORD autoheal1 = FindPattern((PBYTE)"\x0F\x85\x00\x00\x00\x00\xD9\xEE\x51\xBE\x00\x00\x00\x00\xD9\x1C\x24\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00","xx????xxxx????xxxx????x????",0,0);
	DWORD autoheal2 = FindPattern((PBYTE)"\x0F\x8A\x00\x00\x00\x00\xD9\xEE\x51\xBE\x00\x00\x00\x00\xD9\x1C\x24\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xD9\xEE\xA1\x00\x00\x00\x00\x33\x05\x00\x00\x00\x00\x89\x45\x0C\xD8\x5D\x0C","xx????xxxx????xxxx????x????xxx????xx????xxxxxx",0,0);
	DWORD noRestriction = FindPattern((PBYTE)"\x0F\x84\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x83\xB8\x00\x00\x00\x00\x75\x00\x8B\x0D\x00\x00\x00\x00\x85\xC9\x74\x00\x8B\x01","xx????x????xx????x?xx????xxx?xx",0,0);
	
	
	
	
	//======[WRHACKSHIELD]=======//
	DWORD fWRHSHandler      = FindPattern( (PBYTE)"\x68\x00\x00\x00\x00\xBA\x20\x7A\x00\x00\x8B\xC6\xE8\x00\x00\x00\x00", "x????xxx??xxx????", true, 1);
	DWORD dwCRCPATCH        = FindPattern( (PBYTE)"\x75\x00\x6A\x00\x6A\x00\x6A\x00\xB9\x00\x00\x00\x00\x58\xE8\x00", "x?xxx?x?x?xxxxx?", 0, 0);
	DWORD dwWarRockCheck3   = FindPattern( (PBYTE)"\x74\x00\x8B\x15\x00\x00\x00\x00\x85\xD2\x74\x00", "x?xx????xxx?", 0, 0);	
	//worktDWORD dwWarRockCheck2   = FindPattern((PBYTE)"\x55\x8D\xAC\x24\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x85\x00\x00\x00\x00\x8B\x85\x00\x00\x00\x00\x53\x56\x57\x8B\xB8\x00\x00\x00\x00\xBE\x00\x00\x00\x00\x33\xDB\x56\x89\x45\x80\x8D\x85\x00\x00\x00\x00\x53\x50\x88\x9D\x24\x09\x00\x00\xE8\x00\x00\x00\x00\x56\x8D\x85\x00\x00\x00\x00\x53\x50\x88\x9D\x24\x0D\x00\x00\xE8\x00\x00\x00\x00\x56\x8D\x85\x00\x00\x00\x00\x53\x50\x88\x9D\x24\x05\x00\x00","xxxx????x????x????x????xxxx????xx????xxxxx????x????xxxxxxxx????xxxxxxxxx????xxx????xxxxxxxxx????xxx????xxxxxxxx",0,0);

	//======[DrawIndexPrimitve]=======//
	DWORD DIP_HOOK1 = FindPattern((PBYTE)"\x50\x6A\x7D\x00\x50\x6A\x7D\x00\x90\x4C\x7D\x00","xxxxxxxxxxxx",0,0);
	DWORD DIP_HOOK2 = DIP_HOOK1 + 0x4;
	DWORD dwEngineDipCall1 = FindPattern((PBYTE)"\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x08\x53\x55\x56\x57\xA1\x00\x00\x00\x00\x33\xC4\x50\x8D\x44\x24\x1C\x64\xA3\x00\x00\x00\x00\x8B\xF9\x8B\x87\x00\x00\x00\x00\x2B\x87\x00\x00\x00\x00\x8B\xB7\x00\x00\x00\x00\xC1\xF8\x04", "xxx????xx????xxxxxxxxx????xxxxxxxxx????xxxx????xx????xx????xxx",0,0);
	DWORD dwEngineDipCall2 = FindPattern((PBYTE)"\x8B\x86\x00\x00\x00\x00\x2B\x86\x00\x00\x00\x00\x57\x8B\xBE\x00\x00\x00\x00\xC1\xF8\x00\x3B\xF8\x72\x00\x33\xC0\x5F\xC3","xx????xx????xxx????xx?xxx?xxxx",0,0);
	DWORD dwEngineDipCall3 = FindPattern((PBYTE)"\x55\x8B\xEC\x83\xE4\x00\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x00\x53\x56\x57\xA1\x00\x00\x00\x00\x33\xC4\x50\x8D\x44\x24\x00\x64\xA3\x00\x00\x00\x00\x8B\x75\x00\x8B\x86\x00\x00\x00\x00\x81\xC6\x00\x00\x00\x00","xxxxx?x?x????xx????xxx?xxxx????xxxxxx?xx????xx?xx????xx????",0,0);
	DWORD dwEngineDipCall4 = FindPattern((PBYTE)"\x85\xF6\x75\x00\x33\xC0\xC3\x8B\x06\x8B\xCE\xFF\x50\x00\xEB\x00\x3B\x44\x24\x00\x74\x00\x8B\x40\x00\x85\xC0\x75\x00\x32\xC0","xxx?xxxxxxxxx?x?xxx?x?xx?xxx?xx",0,0);
	DWORD dwEngineDipCall5 = FindPattern((PBYTE)"\x55\x8B\xEC\x83\xE4\x00\x83\xEC\x00\x53\x8B\x5D\x00\x8B\x83\x00\x00\x00\x00\x56\x57\xC7\x44\x24\x00","xxxxx?xx?xxx?xx????xxxxx?",0,0);
	DWORD dwEngineDipVar1  = FindPattern((PBYTE)"\x3D\x00\x00\x00\x00\x74\x50\x8B\x40\x04\x85\xC0\x75\xF2\x32\xC0\x0F\xB6\xF0\xF7\xDE\x1B\xF6" , "x????xxxxxxxxxxxxxxxxxx" , 1 , true ) ;
    DWORD dwEngineDipVar2  = FindPattern((PBYTE)"\x8B\x44\x24\x24\x8B\x4B\x1C\x8B\x16\x8B\x52\x30\x50\x8B\x43\x18\x51\x8B\x4C\x24\x28\x50" , "xxxxxxxxxxxxxxxxxxxxxx" , 0 , 0 ) ;
	DWORD EndsceneReturn   = FindPattern((PBYTE)"\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x85\xC9\x75\x00\xB8\x00\x00\x00\x00\xC2\x00\x00\x8B\x44\x24\x00\x8B\x80\x00\x00\x00\x00\x8B\x10","xxxxxxxxxxxxxxxxxx?x????x??xxx?xx????xx",0,0);
	DWORD FuncStart        = FindPattern((PBYTE)"\x51\x53\x8B\x5C\x24\x00\x55\x8B\x6C\x24\x00\x56\x57\x8B\xF8\x85\xED\x74\x00\x8B\xCD\xE8\x00\x00\x00\x00\x89\x44\x24\x00\x85\xC0","xxxxx?xxxx?xxxxxxx?xxx????xxx?xx",0,0);
	/*DWORD dwDIP1     = FindPattern ( ( PBYTE ) "\x6A\xFF\x68\x00\xEC\x86\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x08\x53\x55\x56\x57\xA1\x00\x00\x00\x00" , "xxx?xxxxx????xxxxxxxxx????" , 0 , false ) ;
 DWORD dwDIP2     = FindPattern ( ( PBYTE ) "\x8B\x86\x00\x00\x00\x00\x2B\x86\x00\x00\x00\x00\x57\x8B\xBE\x00\x00\x00\x00\xC1\xF8\x04\x3B\xF8\x72\x04\x33\xC0\x5F\xC3" , "xx????xx????xxx????xxxxxxxxxxx" , 0 , false ) ;
 DWORD dwDIP3     = FindPattern ( ( PBYTE ) "\x55\x8B\xEC\x83\xE4\xF8\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x30\x53\x56\x57" , "xxxxxxxxx????xx????xxxxxxx" , 0 , false ) ;
 DWORD dwDIP4     = FindPattern ( ( PBYTE ) "\x85\xF6\x75\x03\x33\xC0\xC3\x8B\x06\x8B\xCE\xFF\x50\x00\xEB\x09\x3B\x44\x24\x04\x74\x13" , "xxxxxxxxxxxxx?xxxxxxxx" , 0 , false ) ;
 DWORD dwDIP5     = FindPattern ( ( PBYTE ) "\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x14\x53\x8B\x5D\x08\x8B\x83\x00\x00\x00\x00\x56\x57" , "xxxxxxxxxxxxxxx????xx" , 0 , false ) ;*/


	//======[ Struct ]=======//
	DWORD dwPitchs = PitchOffset + 0x4;
	DWORD dwYaws = YawOffset + 0x4;
	DWORD dwViewz = ViewXOffset + 0x8;
	DWORD dwViews = dwViewz + 0x8;
	DWORD dwPosX = FindPattern( (PBYTE)"\x8D\x8F\x00\x00\x00\x00\x8D\x45};","xx????xx",2,true);
	DWORD dwPosY = dwPosX + 0x8;
	DWORD dwPosZ = dwPosY + 0x8;

	Writelog("//------------------------------------------//");
	Writelog("/*------//Adress Logger by xXRusSXx//-------*/");
	Writelog("//------------------------------------------//");
	Writelog("//[Date: %02i.%02i  Time: %02i:%02i ]",xTM->tm_mday ,(xTM->tm_mon)+1 , xTM->tm_hour,xTM->tm_min);
	Writelog("");
	Writelog("//-------------[ Pointers / Bases ]------------//");
	WriteLogX("#define ADR_PlayerPointer                0x%X",Playerpointer2);
	WriteLogX("#define ADR_ServerPointer                0x%X",Serverpointer);
	WriteLogX("#define ADR_HEALTHPOINTER                0x%X",dwHealthPointer);
	WriteLogX("#define ADR_VIEWANGELS                   0x%X",dwViewAngels);
	WriteLogX("#define ADR_DevicePointer                0x%X",dwdevice);
	WriteLogX("#define ADR_RemotePointer                0x%X",dwremotePointer);
	WriteLogX("#define ADR_GlobalPTR                    0x%X",GlobalPointer);
    WriteLogX("#define ADR_StatePTR                     0x%X",StatePointer  );
	WriteLogX("#define ADR_BasePTR                      0x%X",BasePointer   );
	WriteLogX("#define ADR_RoomPTR                      0x%X",RoomPointer   );
	WriteLogX("#define ADR_HealthPTR                    0x%X",dwHealthPointer );
	WriteLogX("#define ADR_UserPTR                      0x%X",dwUserPointer );
	WriteLogX("#define ADR_UserBase                     0x%X",dwUserBase    );
	WriteLogX("#define ADR_MatrixPTR                    0x%X",MatrixPointer );

	Writelog("");
	Writelog("//----------------[ Offsets ]---------------//");
	WriteLogX("#define ADR_OFS_Speed                    0x%X",adrSpeed);
	WriteLogX("#define ADR_OFS_Invisible                0x%X",ofsInvisible);
	WriteLogX("#define ADR_OFS_NoSpawntime              0x%X",adrSpawnTime);
	WriteLogX("#define ADR_OFS_LEVEL                    0x%X",dwLevel);
	WriteLogX("#define ADR_OFS_DINAR                    0x%X",dwDinar);
	WriteLogX("#define ADR_OFS_3DPLAYERVIEW             0x%X",dwView3D);
	WriteLogX("#define ADR_OFS_PLAYERSTATE              0x%X",dwPlayerState);
	WriteLogX("#define ADR_OFS_WEAPONSTATE              0x%X",dwWeaponState);
	WriteLogX("#define ADR_OFS_X                        0x%X",dwOfsX);
	WriteLogX("#define ADR_OFS_Y                        0x%X",dwOfsY);
	WriteLogX("#define ADR_OFS_Z                        0x%X",dwOfsZ);
	WriteLogX("#define ADR_OFS_NOSPREAD                 0x%X",dwNoSpread);
	WriteLogX("#define ADR_OFS_GRAVITY_Z                0x%X",dwGravityZ);
	WriteLogX("#define ADR_OFS_GRAVITY_Y                0x%X",dwGravityY);
	WriteLogX("#define ADR_OFS_GRAVITY_X                0x%X",dwGravityX);
	WriteLogX("#define ADR_OFS_NODELAY                  0x%X",dwNoDelay);
	WriteLogX("#define ADR_OFS_NORELOAD                 0x%X",dwNoReload);
	WriteLogX("#define ADR_OFS_GlobalSize               0x%X",GlobalSizeOffset );
	WriteLogX("#define ADR_OFS_LocalSize                0x%X",LocalSizeOffset );
	WriteLogX("#define ADR_OFS_NoReload                 0x%X",NoReloadOffset );
	WriteLogX("#define ADR_OFS_NoSwitch                 0x%X",NoSwitchOffset );
	WriteLogX("#define ADR_OFS_NoRecoil1                0x%X",NoRecoil1Offset );
	WriteLogX("#define ADR_OFS_NoRecoil2                0x%X",NoRecoil2Offset );
	WriteLogX("#define ADR_OFS_NoRecoil3                0x%X",NoRecoil3Offset );
	/*WriteLogX("#define ADR_OFS_Pos_X                    0x%X",PositionXOffset );
	WriteLogX("#define ADR_OFS_Pos_Y                    0x%X",PositionYOffset );
	WriteLogX("#define ADR_OFS_Pos_Z                    0x%X",PositionZOffset );*/
	WriteLogX("#define ADR_OFS_NFD                      0x%X",NoFallDamageOffset );
	WriteLogX("#define ADR_OFS_ViewMain                 0x%X",ViewMainOffset );
	WriteLogX("#define ADR_OFS_ViewX                    0x%X",ViewXOffset );
	WriteLogX("#define ADR_OFS_ViewZ                    0x%X",ViewZOffset );
	WriteLogX("#define ADR_OFS_ViewY                    0x%X",ViewYOffset );
	WriteLogX("#define ADR_OFS_Slot5                    0x%X",Slot5Offset );
	WriteLogX("#define ADR_OFS_Slot6                    0x%X",Slot6Offset );
	WriteLogX("#define ADR_OFS_Slot7                    0x%X",Slot7Offset );
	WriteLogX("#define ADR_OFS_Slot8                    0x%X",Slot8Offset );
	WriteLogX("#define ADR_OFS_PlayerState              0x%X",PlayerStateOffset );
	WriteLogX("#define ADR_OFS_WeaponMain               0x%X",WeaponMainOffset );
	WriteLogX("#define ADR_OFS_Weapon1                  0x%X",Weapon1Offset );
	WriteLogX("#define ADR_OFS_Weapon2                  0x%X",Weapon2Offset );
	WriteLogX("#define ADR_OFS_Weapon3                  0x%X",Weapon3Offset );
	WriteLogX("#define ADR_OFS_UserName                 0x%X",UserNameOffset );
	/*WriteLogX("#define ADR_OFS_Gravity_Z                0x%X",dwGravZ );
	WriteLogX("#define ADR_OFS_Gravity_Y                0x%X",dwGravY );
	WriteLogX("#define ADR_OFS_Gravity_X                0x%X",dwGravX );*/
	WriteLogX("#define ADR_OFS_Invisible                0x%X",InvisibleOffset );
	/*WriteLogX("#define ADR_OFS_ReadyRoomSize            0x%X",ReadyRoomSize );
	WriteLogX("#define ADR_OFS_StartRoomSize            0x%X",StartRoomSize );
	WriteLogX("#define ADR_OFS_Level                    0x%X",LevelOffset );
	WriteLogX("#define ADR_OFS_Dinar                    0x%X",DinarOffset );*/
	WriteLogX("#define ADR_OFS_Pitch                    0x%X",PitchOffset );
	WriteLogX("#define ADR_OFS_Yaw                      0x%X",YawOffset );
	WriteLogX("#define ADR_OFS_PlayerView               0x%X",PlayerViewOffset );
	WriteLogX("#define ADR_OFS_PlayerSpeed              0x%X",PlayerSpeedOffset );
	WriteLogX("#define ADR_OFS_NoSpread                 0x%X",NoSpreadOffset );
	WriteLogX("#define ADR_OFS_RoomMaster               0x%X",dwRoomMaster );
	WriteLogX("#define ADR_OFS_Premium1                 0x%X",dwPremium1 );
	WriteLogX("#define ADR_OFS_Premium2                 0x%X",dwPremium2 );
	WriteLogX("#define ADR_OFS_WeaponDamage             0x%X",dwWeaponDamage );
	WriteLogX("#define ADR_OFS_WeaponDefence            0x%X",dwWeaponDefence );
	WriteLogX("#define ADR_OFS_WeaponRange              0x%X",dwWeaponRange );
	WriteLogX("#define ADR_OFS_AmmoNumber               0x%X",dwAmmoNumber );
	WriteLogX("#define ADR_OFS_MagazineNumber           0x%X",dwMagazineNumber );
	WriteLogX("#define ADR_OFS_EffectRange              0x%X",dwEffectRange );
	WriteLogX("#define ADR_OFS_Parabola                 0x%X",dwParabola );
	WriteLogX("#define ADR_OFS_ShotSpeed                0x%X",dwShotSpeed );
	WriteLogX("#define ADR_OFS_WeaponWheight            0x%X",dwWeaponWheight );
	WriteLogX("#define ADR_OFS_DevicePTR                0x%X",ofsDevice);
	WriteLogX("#define ADR_OFS_Mouse                    0x%X",mouseIngame);
	Writelog("");
	Writelog("//---------------[ Adresses ]---------------//");
	WriteLogX("#define ADR_SpawnTime                    0x%X",adrSpawnTime);
	//WriteLogX("#define ADR_NoDelay                    0x%X",adrFireDelay);
	WriteLogX("#define ADR_UnlAmmo                      0x%X",adrUnlimitedAmmo);
	WriteLogX("#define ADR_NoSpawn1                     0x%X",dwNoSpawnWait1 );
	WriteLogX("#define ADR_NoSpawn2                     0x%X",dwNoSpawnWait2 );
	WriteLogX("#define ADR_NoSpawn3                     0x%X",dwNoSpawnWait3 );
	WriteLogX("#define ADR_NoBounds1                    0x%X",NoBounds1);
	WriteLogX("#define ADR_NoBounds2                    0x%X",NoBounds2);
	WriteLogX("#define ADR_NoBounds3                    0x%X",NoBounds3);
	WriteLogX("#define ADR_NoWater1                     0x%X",NoWaterMemory1 );
	WriteLogX("#define ADR_NoWater2                     0x%X",NoWaterMemory2 );
	WriteLogX("#define ADR_WTW                          0x%X",WalkThroughWallsMemory );
	WriteLogX("#define ADR_FastLockOn                   0x%X",FastLockOnMemory );
	WriteLogX("#define ADR_SuperNoSpread                0x%X",SuperNoSpreadMemory );
	WriteLogX("#define ADR_PlantAnyWhere                0x%X",PlantAnyWhereMemory );
	WriteLogX("#define ADR_DefuseAnyWhere               0x%X",DefuseAnyWhereMemory );
	WriteLogX("#define ADR_AutoRepair                   0x%X",AutoRepairMemory );
	WriteLogX("#define ADR_Scope                        0x%X",ScopeMemory );
	WriteLogX("#define ADR_Artilery                     0x%X",Artilery		);
	WriteLogX("#define ADR_FastHealth                   0x%X",FastHealthMemory );
	WriteLogX("#define ADR_FastAmmo                     0x%X",FastAmmoMemory );
	WriteLogX("#define ADR_FastFlag                     0x%X",FastFlagMemory );
	WriteLogX("#define ADR_WUW                          0x%X",dwWUW );
	WriteLogX("#define ADR_UnlAmmo                      0x%X",UnlAmmoMemory );
	WriteLogX("#define ADR_Boneshot                     0x%X",dwBoneShot );
	WriteLogX("#define ADR_STW                          0x%X",dwSTW );
	WriteLogX("#define ADR_Speed                        0x%X",dwSpeed );
	WriteLogX("#define ADR_DeathCam                     0x%X",dwDeathCam );
	WriteLogX("#define ADR_Explosion                    0x%X",dwImmExplosion  );
	WriteLogX("#define ADR_PlayerProne                  0x%X",dwPlayerProne  );
	WriteLogX("#define ADR_StaminaRefill                0x%X",dwStaminaRefill  );
	WriteLogX("#define ADR_AntiRadar                    0x%X",dwAntiRadar  );
	WriteLogX("#define ADR_QuickPlant                   0x%X",dwQuickPlant  );
	WriteLogX("#define ADR_BigCarName                   0x%X",dwBigCarName  );
	WriteLogX("#define ADR_AutoStart                    0x%X",dwAUTOStart  );
	WriteLogX("#define ADR_WeaponShot1                  0x%X",dwWeaponShot1  );
	WriteLogX("#define ADR_WeaponShot2                  0x%X",dwWeaponShot2  );
	WriteLogX("#define ADR_Breaklimit                   0x%X",dwBreaklimit  );
	WriteLogX("#define ADR_FullBright1                  0x%X",dwFullBright   );
	WriteLogX("#define ADR_FullBright2                  0x%X",dwFullBright2   );
	WriteLogX("#define ADR_FullBright3                  0x%X",dwFullBright3   );
	WriteLogX("#define ADR_GlassWalls                   0x%X",dwGlassWall   );
	WriteLogX("#define ADR_WeaponGravity                0x%X",dwWeaponGravity  );
	WriteLogX("#define ADR_SilentWalk                   0x%X",dwSilentWalk   );
	WriteLogX("#define ADR_LadderSpeed                  0x%X",dwLadderQuickly  );
	WriteLogX("#define ADR_CrossHair                    0x%X",dwCrossHair   );
	WriteLogX("#define ADR_ColorShot                    0x%X",dwColorShot  );
	WriteLogX("#define ADR_DeadSpinner                  0x%X",dwDeadSpinner  );
	WriteLogX("#define ADR_HideWeapon                   0x%X",dwHideWeapon  );
	WriteLogX("#define ADR_ChangeRoll                   0x%X",dwChangeRoll  );
	WriteLogX("#define ADR_WTH                          0x%X",dwWTH  );
	WriteLogX("#define ADR_RollSpeed                    0x%X",dwRollSpeed   );
	WriteLogX("#define ADR_VirtualJump                  0x%X",dwVirtualJump   );
	WriteLogX("#define ADR_Drunk                        0x%X",dwImDrunk    );
	WriteLogX("#define ADR_SniperAmmo                   0x%X",dwSniperAmmo  );
	WriteLogX("#define ADR_ExtraAmmo1                   0x%X",dwExtraAmmo1  );
	WriteLogX("#define ADR_ExtraAmmo2                   0x%X",dwExtraAmmo2  );
	WriteLogX("#define ADR_AssaultAmmo                  0x%X",dwAssaultAmmo  );
	WriteLogX("#define ADR_Bandage                      0x%X",dwBandage   );
	WriteLogX("#define ADR_ClanTag1                     0x%X",dwClanTag1  );
	WriteLogX("#define ADR_ClanTag2                     0x%X",dwClanTag2  );
	WriteLogX("#define ADR_ClanTag3                     0x%X",dwClanTag3  );
	WriteLogX("#define ADR_ClanTag4                     0x%X",dwClanTag4  );
	WriteLogX("#define ADR_ClanTag5                     0x%X",dwClanTag5  );
	WriteLogX("#define ADR_ClanTag6                     0x%X",dwClanTag6  );
	WriteLogX("#define ADR_RoomMaster                   0x%X",RoomMaster  );
	WriteLogX("#define ADR_Swim1                        0x%X",Swim1  );
	WriteLogX("#define ADR_Swim2                        0x%X",Swim2  );
	WriteLogX("#define ADR_CqcProne                     0x%X",cqcProne  );
	WriteLogX("#define ADR_Disable_KickMesssage2        0x%X",KickMessage2 );
	WriteLogX("#define ADR_GameMode                     0x%X",gamemode );
	WriteLogX("#define ADR_Packet                       0x%X",packet );
	Writelog("");
	Writelog("//----------------[ User ]-----------------//");
	Writelog("");
	WriteLogX("#define ADR_User_Health                  0x%X",HealthUserInfo    );
	WriteLogX("#define ADR_User_Name                    0x%X",NameUserInfo    );
	WriteLogX("#define ADR_User_Points                  0x%X",PointsUserInfo    );
	WriteLogX("#define ADR_User_Ping                    0x%X",PingUserInfo    );
	Writelog("");
	Writelog("//-----------------[ D3D ]------------------//");
	WriteLogX("#define ADR_D3DUserName                  0x%X",adrD3DUsername);
	Writelog("");
	Writelog("//--------------[ WeaponBinder ]-------------//");
	Writelog("");
	WriteLogX("#define ADR_ClassBase                    0x%X",dwClassBase     );
	WriteLogX("#define ADR_WeaponBase                   0x%X",dwWeaponBase     );
	WriteLogX("#define ADR_OFS_SlotBase                 0x%X",SlotBaseOffset );
	Writelog("");
	Writelog("//-----------------[ ASM ]-----------------//");
	Writelog("");
	WriteLogX("#define ADR_ASM_QuickDefuse              0x%X",dwQuickDefuseASM );
	WriteLogX("#define ADR_ASM_Bullets                  0x%X",dwBullets );
	WriteLogX("#define ADR_ASM_WTW                      0x%X",dwWTWASM  );
	WriteLogX("#define ADR_ASM_STW                      0x%X",dwSTWASM  );
	WriteLogX("#define ADR_ASM_BackToLobby              0x%X",dwBacktolobby   );
	WriteLogX("#define ADR_ASM_AlwaysCrossHair          0x%X",dwAlwaysCrossAsm  );
	WriteLogX("#define ADR_ASM_EngineText               0x%X",dwEngineText  );
	WriteLogX("#define ADR_ASM_MessageBox               0x%X",dwMessageBox  );
	WriteLogX("#define ADR_ASM_UnlAmmo                  0x%X",dwUnlAmmo  );
	WriteLogX("#define ADR_ASM_SwitchTime               0x%X",dwSwitchTime   );
	WriteLogX("#define ADR_ASM_OPK                      0x%X",dwOPKAsm   );
	WriteLogX("#define ADR_ASM_AutoStart                0x%X",dwAUTOStart  );
	WriteLogX("#define ADR_ASM_SuperCarSound            0x%X",dwSuperCarSound  );
	WriteLogX("#define ADR_ASM_DamageAs                 0x%X",Damage  );
	WriteLogX("#define ADR_ASM_VehJump1                 0x%X",vehicleJump1 );
	WriteLogX("#define ADR_ASM_VehJump2                 0x%X",vehicleJump2 );
	WriteLogX("#define ADR_ASM_VehNoDamage              0x%X",vehicleNoDamage );
	WriteLogX("#define ADR_ASM_SuperCar1                0x%X",SuperCar1 );
	WriteLogX("#define ADR_ASM_SuperCar2                0x%X",SuperCar2 );
	WriteLogX("#define ADR_ASM_SuperCar3                0x%X",SuperCar3 );
	WriteLogX("#define ADR_ASM_STW1                     0x%X",STW1 );
	WriteLogX("#define ADR_ASM_STW2                     0x%X",STW2 );
	WriteLogX("#define ADR_ASM_EventRoom                0x%X",EventRoom );
	WriteLogX("#define ADR_ASM_EventRoom2               0x%X",EventRoom2 );
	WriteLogX("#define ADR_ASM_AiKnifeRoom              0x%X",AiKniferoom );
	WriteLogX("#define ADR_ASM_UnlOxygen                0x%X",UnlOxygen );
	WriteLogX("#define ADR_ASM_Artillery0               0x%X",artillery0 );
	WriteLogX("#define ADR_ASM_Artillery1               0x%X",artillery1 );
	WriteLogX("#define ADR_ASM_Artillery2               0x%X",artillery2 );
	WriteLogX("#define ADR_ASM_Artillery3               0x%X",artillery3 );
	WriteLogX("#define ADR_ASM_Artillery4               0x%X",artillery4 );
	WriteLogX("#define ADR_ASM_Artillery5               0x%X",artillery5 );
	WriteLogX("#define ADR_ASM_Artillery6               0x%X",artillery6 );
	WriteLogX("#define ADR_ASM_Artillery7               0x%X",artillery7 );
	WriteLogX("#define ADR_ASM_UserKill                 0x%X",userKill );
	WriteLogX("#define ADR_ASM_FakeKick                 0x%X",fakeKick );
	WriteLogX("#define ADR_ASM_SpamBot                  0x%X",spamBot );
	WriteLogX("#define ADR_ASM_OPK1                     0x%X",opk1 );
	WriteLogX("#define ADR_ASM_OPK2                     0x%X",opk2 );
	WriteLogX("#define ADR_ASM_OPK3                     0x%X",opk3 );
	WriteLogX("#define ADR_ASM_AntiOverHeat             0x%X",antioverheat );
	WriteLogX("#define ADR_ASM_AutoRepair1              0x%X",autorepair1 );
	WriteLogX("#define ADR_ASM_AutoRepair2              0x%X",autorepair2 );
	WriteLogX("#define ADR_ASM_AutoRepair3              0x%X",autorepair3 );
	WriteLogX("#define ADR_ASM_AutoAmmo1                0x%X",autoammo1 );
	WriteLogX("#define ADR_ASM_AutoAmmo2                0x%X",autoammo2 );
	WriteLogX("#define ADR_ASM_AutoHeal1                0x%X",autoheal1 );
	WriteLogX("#define ADR_ASM_AutoHeal2                0x%X",autoheal2 );
	WriteLogX("#define ADR_ASM_NoRestriction            0x%X",noRestriction );

	Writelog("");
	Writelog("//----------------[ AntiAbnormal ]-----------------//");
	WriteLogX("#define ADR_AntiAbnormal1                0x%X",AntiAbnormal1 );
	WriteLogX("#define ADR_AntiAbnormal2                0x%X",AntiAbnormal2 );
	WriteLogX("#define ADR_AntiAbnormal3                0x%X",AntiAbnormal3 );
	WriteLogX("#define ADR_AntiAbnormal4                0x%X",AntiAbnormal4 );
	Writelog("");
	Writelog("//----------------[ DrawIndexPrimitive ]-----------------//");
	WriteLogX("#define ADR_ASM_HOOK1                    0x%X",DIP_HOOK1 );
	WriteLogX("#define ADR_ASM_HOOK2                    0x%X",DIP_HOOK2 );
	WriteLogX("#define ADR_ASM_EngineDipCall1           0x%X",dwEngineDipCall1 );
	WriteLogX("#define ADR_ASM_EngineDipCall2           0x%X",dwEngineDipCall2 );
	WriteLogX("#define ADR_ASM_EngineDipCall3           0x%X",dwEngineDipCall3 );
	WriteLogX("#define ADR_ASM_EngineDipCall4           0x%X",dwEngineDipCall4 );
	WriteLogX("#define ADR_ASM_EngineDipCall5           0x%X",dwEngineDipCall5 );
	WriteLogX("#define ADR_EngineDipVar1                0x%X",dwEngineDipVar1 );
	WriteLogX("#define ADR_ASM_EngineDipVar2            0x%X",dwEngineDipVar2 );
	WriteLogX("#define ADR_ASM_EndsceneReturn           0x%X",EndsceneReturn );
	WriteLogX("#define ADR_ASM_FuncStart                0x%X",FuncStart );
	Writelog("");
	Writelog("//---------------[ BypassWR ]---------------//");
	WriteLogX("#define ADR_WarRockCheck2                0x%X",fWRHSHandler);
	//WriteLogX("#define ADR_WarRockCheck2                0x%X",dwWarRockCheck2 );
	WriteLogX("#define ADR_WarRockCheck3                0x%X",dwWarRockCheck3);
	WriteLogX("#define ADR_CRCPatch                     0x%X",dwCRCPATCH );
	Writelog("");


	Writelog("//---------------[ Structs ]---------------//");
	Writelog("");
	Writelog("struct CPlayer");
	Writelog("{");
	Writelog("    CHAR xXRusSXx1[0x%X];//0x00",PlayerStateOffset);
	Writelog("    BYTE PlayerState;//0x%X",PlayerStateOffset);
	Writelog("    CHAR xXRusSXx2[0x%X];//0x%X",(PitchOffset-PlayerStateOffset+0x1),(PlayerStateOffset+0x1));
	Writelog("    FLOAT Pitch;//0x%X",PitchOffset);
	Writelog("    CHAR xXRusSXx3[0x%X];//0x%X",(YawOffset-dwPitchs),(PitchOffset+0x4));
	Writelog("    FLOAT Yaw;//0x%X",YawOffset);
	Writelog("    CHAR xXRusSXx4[0x%X];//0x%X",(ViewXOffset-dwYaws),(YawOffset+0x4));
	Writelog("    FLOAT ViewX;//0x%X",ViewXOffset);
	Writelog("    FLOAT ViewY;//0x%X",ViewYOffset);
	Writelog("    FLOAT ViewZ;//0x%X",ViewZOffset);
	Writelog("    CHAR xXRusSXx6[0x%X];//0x%X",(PositionXOffset-(ViewZOffset+0x4)),(ViewZOffset+0x4));
	Writelog("    FLOAT PosX;//0x%X",PositionXOffset);
	Writelog("    CHAR xXRusSXx7[0x%X];//0x%X",(PositionYOffset-(PositionXOffset+0x4)),(PositionXOffset+0x4));
	Writelog("    FLOAT PosY;//0x%X",PositionYOffset);
	Writelog("    CHAR xXRusSXx8[0x%X];//0x%X",(PositionZOffset-(PositionXOffset+0x4)),(PositionYOffset+0x4));
	Writelog("    FLOAT PosZ;//0x%X",PositionZOffset);
	Writelog("};");
	Writelog("struct CBase");
	Writelog("{");
	Writelog("	CPlayer* pLocal; ");
	Writelog("	char* xXRusSXx[0x%X];",(dwremotePointer-Playerpointer-0x4));
	Writelog("	CPlayer** pGlobal;");
	Writelog("};");
	Writelog("CBase* p_Player = (CBase*)(0x0%X);",Playerpointer);
	
	Writelog("");
	Writelog("//Addresses Logged: %i >< Addresses Failed: %i//",iLogged,fLogged);
	Writelog("//---Special Thanks to:  Kazbah, Exodus, CyberRazzer, etc---//");
	Writelog("");
	ShellExecuteA(GetForegroundWindow(),"open",GetDirectoryFile("xXRusSXxAddresses.txt"),0,0,SW_MAXIMIZE);
	exit(0);
}


BOOL WINAPI DllMain ( HMODULE hDll, DWORD dwReason, LPVOID lpReserved )
{
	DisableThreadLibraryCalls(hDll);
	if (dwReason==DLL_PROCESS_ATTACH)
	{
		logging(hDll);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SearchPatterns, NULL, NULL, NULL);
	}
	return TRUE;
}
