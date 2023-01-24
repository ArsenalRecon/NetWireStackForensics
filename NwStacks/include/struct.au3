
; a general OS independent struct
Global $tagNWSTACK_VALIDATION = "align 1;" _
&"byte 0000[" & 0x2b1c & "];" _ ; fill
&"uint 2b1c;" _ ; last ret address pushed on stack within main func (00401092)
&"uint 2b20;" _ ; fill
&"uint 2b24;" _ ; fill
&"byte 2b28[" & 0x10 & "];" _ ; fill
&"uint 2b38;" _ ; ptr buffer 1
&"uint 2b3c;" _ ; ptr buffer 0
&"uint 2b40;" _ ; fill
&"uint 2b44;" _ ; VA 00427244
&"byte 2b48[" & 0x14 & "];" _ ; fill
&"byte 2b5c[" & 0x1 & "];" _ ; control
&"byte 2b5d[" & 0x3 & "];" _ ; fill
&"char 2b60[" & 0x40 & "];" _ ; buffer 0
&"char 2ba0[" & 0x20 & "];" _ ; buffer 1
&"byte 2bc0[" & 0xe4 & "];" _ ; fill
&"char 2ca4[" & 0x100 & "];" _ ; buffer 2
&"byte 2da4[" & 0x11ac & "];" _ ; fill
&"uint 3f50;" _ ; VA 0040109E
&"uint 3f54;" _ ; ptr PEB
&"uint 3f58;" _ ; unk
&"uint 3f5c;" _ ; va
&"uint 3f60;" _ ; unk
&"uint 3f64;" _ ; unk
&"uint 3f68;" _ ; unk
&"uint 3f6c;" _ ; payload size
&"uint 3f70;" _ ; unk
&"uint 3f74;" _ ; unk
&"uint 3f78;" _ ; socket descriptor
&"byte 3f7c[" & 0x1 & "];" _ ; control
&"byte 3f7d[" & 0x2ffff & "];" _ ; payload with max size per block
&"uint 33f7c;" _ ; xxxxxxxx
&"uint 33f80;" _ ; 0003002c
&"uint 33f84;" _ ; xxxxxxxx
&"uint 33f88;" ; VA 00402BD5

; originally made for Windows 7 analysis - only partially used
Global $tagNWSTACK = "align 1;" _
&"byte 0000[" & 0x1630 & "];" _ ; fill
&"byte 1630[" & 0x8 & "];" _ ;ffffffff 17000000
&"byte 1638[" & 0x230 & "];" _ ; fill
&"byte 1868[" & 0x8 & "];" _ ; 808b2de5 ffffffff
&"byte 1870[" & 0x22c & "];" _ ; fill
&"uint 1a9c;" _ ; VA 00408D5F
&"uint 1aa0;" _ ; VA 0042430C
&"byte 1aa4[" & 0xc & "];" _ ; fill
&"byte 1ab0[" & 0x8 & "];" _ ; ffffffff 00000000
&"byte 1ab8[" & 0x34 & "];" _ ; fill
&"uint 1aec;" _ ; VA 004095E4
&"uint 1af0;" _ ; socket descriptor
&"uint 1af4;" _ ; control
&"uint 1af8;" _ ; fill
&"uint 1afc;" _ ; data length
&"byte 1b00[" & 0xc & "];" _ ; fill
&"byte 1b0c[" & 0x40 & "];" _ ; data -> currently oversized
&"byte 1b4c[" & 0x314 & "];" _ ; fill
&"uint 1e60;" _ ; length of full browse path
&"uint 1e64;" _ ; address for end of path
&"byte 1e68[" & 0x10 & "];" _ ; fill
&"uint 1e78;" _ ; unk
&"uint 1e7c;" _ ; unk
&"byte 1e80[" & 0x10 & "];" _ ; fill
&"uint 1e90;" _ ; length of full browse path
&"byte 1e94[" & 0x40 & "];" _ ; fill
&"uint 1ed4;" _ ; address for end of path
&"byte 1ed8[" & 0x10 & "];" _ ; fill
&"uint 1ee8;" _ ; address for end of path
&"byte 1eec[" & 0x1c & "];" _ ; fill
&"uint 1f08;" _ ; length of full browse path
&"byte 1f0c[" & 0x10 & "];" _ ; fill
&"byte 1f1c[" & 0xd4 & "];" _ ; full browse path including *.*
&"byte 1ff0[" & 0x200 & "];" _ ; fill
&"uint 21f0;" _ ; unk
&"uint 21f4;" _ ; with FE browse -> ZwQueryDirectoryFile -> FILE_BOTH_DIR_INFORMATION from here (for win81 start is 0xc earlier)
&"uint 21f8;" _ ;
&"uint64 21fc;" _ ; timestamp
&"uint64 2204;" _ ; timestamp
&"uint64 220c;" _ ; timestamp
&"uint64 2214;" _ ; timestamp
&"byte 221c[" & 0x14 & "];" _ ; fill
&"ushort 2230;" _ ; length of name for last item
&"byte 2232[" & 0x20 & "];" _ ; fill
&"byte 2252[" & 0x100 & "];" _ ; A possible remnant of the first browse command when opening a volume -> name of last item (also including slack of previous items)
&"byte 2352[" & 0x14e & "];" _ ; fill
&"uint 24a0;" _ ; unk
&"uint 24a4;" _ ; unk
&"uint64 24a8;" _ ; timestamp
&"uint64 24b0;" _ ; timestamp
&"byte 24b8[" & 0x244 & "];" _ ; fill
&"uint 26fc;" _ ; va 00409A89 (with A6 or CC control which initialize a browse)
&"uint 2700;" _ ;
&"uint 2704;" _ ;
&"uint 2708;" _ ;
&"uint 270c;" _ ;
&"uint 2710;" _ ;
&"uint 2714;" _ ; unk
&"uint 2718;" _ ;
&"byte 271c[" & 0x54 & "];" _ ; fill
&"uint 2770;" _ ; unk
&"uint 2774;" _ ; unk (start return data to FE browse)
&"uint 2778;" _ ; unk
&"uint 277c;" _ ; unk
&"uint 2780;" _ ; A6 - WIN32_FIND_DATAA structure
&"uint64 2784;" _ ; timestamp
&"uint64 278c;" _ ; timestamp
&"uint64 2794;" _ ; timestamp
&"byte 279c[" & 0x10 & "];" _ ; fill
&"byte 27ac[" & 0x44 & "];" _ ; name
&"byte 27f0[" & 0xa8 & "];" _ ; fill
&"byte 2898[" & 0x8 & "];" _ ; 808b2de5 ffffffff
&"byte 28a0[" & 0x44 & "];" _ ; fill
&"char 28e4[" & 0x20 & "];" _ ; tmp timestamp for item x for formatted return data with A6
&"byte 2904[" & 0x40 & "];" _ ; formatted return data for item x with A6
&"byte 2944[" & 0x7c & "];" _ ; fill
&"uint 29c0;" _ ; unk
&"uint 29c4;" _ ; unk
&"uint 29c8;" _ ; unk
&"uint 29cc;" _ ; unk
&"uint 29d0;" _ ; unk
&"uint 29d4;" _ ; unk
&"uint 29d8;" _ ; unk
&"uint 29dc;" _ ; unk
&"uint 29e0;" _ ; unk
&"byte 29e4[" & 0xc & "];" _ ; hostname if no particular controls have been used
&"byte 29f0[" & 0xdc & "];" _ ; fill
&"uint 2acc;" _ ; VA 00408D5F
&"byte 2ad0[" & 0x10 & "];" _ ; fill
&"uint 2ae0;" _ ; unk
&"uint 2ae4;" _ ; unk
&"uint 2ae8;" _ ; unk
&"uint 2aec;" _ ; unk
&"uint 2af0;" _ ; unk
&"uint 2af4;" _ ; unk
&"byte 2af8[" & 0x8 & "];" _ ; if 2af4 is 1 it is upload and first 3 bytes is size of file for uploads (depends on va at 0x2aec) / for download it is uint64 timestamp
&"uint 2b00;" _ ; unk
&"uint 2b04;" _ ; unk
&"uint 2b08;" _ ; unk
&"uint 2b0c;" _ ; unk
&"uint 2b10;" _ ; ptr PEB
&"uint 2b14;" _ ; unk
&"uint 2b18;" _ ; ptr PEB when remote shell
&"uint 2b1c;" _ ; last ret address pushed on stack within main func (00401092)
&"uint 2b20;" _ ; fill (socket descriptor in regular ping scenarios..)
&"uint 2b24;" _ ; fill (control in regular ping scenarios..)
&"byte 2b28[" & 0x10 & "];" _ ; fill
&"uint 2b38;" _ ; ptr buffer 1
&"uint 2b3c;" _ ; ptr buffer 0
&"uint 2b40;" _ ; fill
&"uint 2b44;" _ ; VA 00427244
&"byte 2b48[" & 0x14 & "];" _ ; fill
&"byte 2b5c[" & 0x1 & "];" _ ; control
&"byte 2b5d[" & 0x3 & "];" _ ; fill
&"char 2b60[" & 0x40 & "];" _ ; buffer 0
&"char 2ba0[" & 0x20 & "];" _ ; buffer 1
&"byte 2bc0[" & 0x20 & "];" _ ; fill, used for detecting wipe operations in buffer 1
&"byte 2be0[" & 0xc0 & "];" _ ; fill, used for detecting wipe operations in buffer 1
&"byte 2ca0[" & 0x4 & "];" _ ; fill
&"byte 2ca4[" & 0x100 & "];" _ ; buffer 2
&"byte 2da4[" & 0x100 & "];" _ ; fill, used for detecting wipe operations in buffer 2
&"byte 2ea4[" & 0x44 & "];" _ ; fill
&"byte 2ee8[" & 0x18 & "];" _ ; print formatting
&"byte 2f00[" & 0x100 & "];" _ ; buffer 3
&"byte 3000[" & 0x68 & "];" _ ; fill, used for detecting wipe operations in buffer 3
&"char 3068[" & 0x20 & "];" _ ; possible c2 domain name remnant from the initial connection attempts to c2
&"byte 3088[" & 0xa28 & "];" _ ; fill, used for detecting wipe operations in buffer 3
&"byte 3ab0[" & 0x140 & "];" _ ; fill, overwritten by the 1 min socket loop
&"byte 3bf0[" & 0x5c & "];" _ ; fill, socket operations overwriting this area
&"uint64 3c4c;" _ ; timestamp last socket event
&"byte 3c54[" & 0x188 & "];" _ ; fill
&"uint 3ddc;" _ ; VA 0040900E
&"byte 3de0[" & 0x14c & "];" _ ; fill
&"uint 3f2c;" _ ; VA 00409179
&"byte 3f30[" & 0xc & "];" _ ; fill
&"uint 3f3c;" _ ; VA 0040B2A3
&"byte 3f40[" & 0x10 & "];" _ ; fill
&"uint 3f50;" _ ; VA 0040109E
&"uint 3f54;" _ ; ptr PEB
&"uint 3f58;" _ ; unk
&"uint 3f5c;" _ ; va
&"uint 3f60;" _ ; unk
&"uint 3f64;" _ ; unk
&"uint 3f68;" _ ; unk
&"uint 3f6c;" _ ; payload size
&"uint 3f70;" _ ; unk
&"uint 3f74;" _ ; unk
&"uint 3f78;" _ ; socket descriptor
&"byte 3f7c[" & 0x1 & "];" _ ; control
&"byte 3f7d[" & 0x2ffff & "];" _ ; payload with max size per block
&"uint 33f7c;" _ ; 00000000
&"uint 33f80;" _ ; 0003002c
&"uint 33f84;" _ ; xxxxxxxx
&"uint 33f88;" _ ; VA 00402BD5
&"byte 33f8c[" & 0x50 & "];" _ ; fill
&"uint 33fdc;" _ ; VA 00402BCB
&"uint 33fe0;" _ ; ptr PEB
&"byte 33fe4[" & 0x10 & "];" _ ; fill
&"uint 33ff4;" _ ; VA 00402BCB
&"uint 33ff8;" _ ; ptr PEB
&"uint 33ffc;" ; zero end
