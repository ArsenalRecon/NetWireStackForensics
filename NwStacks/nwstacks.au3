#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=C:\Program Files (x86)\AutoIt3\Icons\au3.ico
#AutoIt3Wrapper_Outfile=nwstacks32.exe
#AutoIt3Wrapper_Outfile_x64=nwstacks64.exe
#AutoIt3Wrapper_Compile_Both=y
#AutoIt3Wrapper_UseX64=y
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Res_Comment=NetWire stack analysis tool
#AutoIt3Wrapper_Res_Description=NetWire stack analysis tool
#AutoIt3Wrapper_Res_Fileversion=1.0.0.0
#AutoIt3Wrapper_AU3Check_Parameters=-w 3 -w 5
#AutoIt3Wrapper_Run_Au3Stripper=y
#Au3Stripper_Parameters=/sf /sv /rm /pe
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

#include <WinAPIConv.au3>
#include <String.au3>
#Include <WinAPIEx.au3>
#include <Array.au3>
#include <Date.au3>
#include "include\struct.au3"
#include "include\wintime.au3"

Global $ProgVersion = "NwStacks 1.0.0.0"
Global $RegExPatternHexNotNull = "[1-9a-fA-F]"
Global $OutPutPath
Global $de = "|"
Global $ade = Asc($de)
Global $DateTimeFormat = 6, $TimestampPrecision = 3, $PrecisionSeparator2 = ""
Global $TimestampErrorVal = "0000-00-00 00:00:00.0000000"
Global $sPSScript = @ScriptDir & "\sigscan.ps1"


If Not FileExists($sPSScript) Then
	ConsoleWrite("Could not find script: " & $sPSScript & @CRLF)
	Exit
EndIf

Global $targetFile, $targetHostname, $winVersion, $dumpAll=False

If $cmdline[0] > 0 Then
	_GetInputParams()
Else
	_PrintHelp()
EndIf

$TimestampStart = @YEAR & "-" & @MON & "-" & @MDAY & "_" & @HOUR & "-" & @MIN & "-" & @SEC
$OutPutPath = @ScriptDir & "\NwStacks_" & $TimestampStart

DirCreate($OutPutPath)
If @error Then Exit

Global $logfile = FileOpen($OutPutPath & "\nwstacks.log",2+32)
FileWrite($logfile, "Running " & $ProgVersion & @CRLF)

_main($targetFile, $targetHostname)


Func _main($targetFile, $targetHostname)

	Local $regexHexStart = "[\x97-\xE8].{3}"
	Local $regexHexEnd = "\x00\x00\x00"
	Local $Timerstart = TimerInit()

	ConsoleWrite("Converting target strings to hex and regex pattern" & @CRLF)
	Local $hex = _StringToHex($targetHostname)
	Local $regexHex = $regexHexStart & _HexToRegExFormat($hex) & $regexHexEnd

	Local $arr_hits[0][2]

	ConsoleWrite("Searching the input file by regex..." & @CRLF)
	Local $matches = _Signature2Array_v2($targetFile, $arr_hits, "", $regexHex)

	_DebugOut("Signature hits: " & $matches & @CRLF)

	_ArraySort($arr_hits)

	_DebugOut("Scanning for signatures took " & _WinAPI_StrFromTimeInterval(TimerDiff($Timerstart)) & @CRLF)

	$Timerstart = TimerInit()

	Local $hFile = _WinAPI_CreateFile("\\.\" & $targetFile, 2, 2, 2)
	If $hFile = 0 Then Exit

	Local $filesize = _WinAPI_GetFileSizeEx($hFile)
	_DebugOut("Filesize: " & $filesize & @CRLF)

	Local $offsetRecalc
	For $i = 0 To UBound($arr_hits) - 1
		$offsetRecalc = $arr_hits[$i][0] + 4 - 11104
		ConsoleWrite("-- Scanning signature hit " & $i & " at offset 0x" & Hex($offsetRecalc) & @CRLF)
		_AnalyzeOffset($hFile, $offsetRecalc, 0x35000)
	Next

	_DebugOut(@CRLF & "Parsing took " & _WinAPI_StrFromTimeInterval(TimerDiff($Timerstart)) & @CRLF)
	_WinAPI_CloseHandle($hFile)
EndFunc


Func _PreValidation($offset, $tBuffer, ByRef $aStruct)

	Local $pStack = DllStructCreate($tagNWSTACK_VALIDATION, DllStructGetPtr($tBuffer))
	If @error Then
		ConsoleWrite("Error in DllStructCreate: " & @error & @CRLF)
		Return
	EndIf

	FileWrite($logfile, @CRLF & "------ Pre validation of signature hit at 0x" & Hex($offset) & @CRLF)

	Local $2b1c = DllStructGetData($pStack, "2b1c") ; last ret address pushed on stack within main func (00401092)
	Local $2b38 = DllStructGetData($pStack, "2b38") ; ptr buffer 1
	Local $2b3c = DllStructGetData($pStack, "2b3c") ; ptr buffer 0
	Local $2b44 = DllStructGetData($pStack, "2b44") ; VA last ret address after call, most often 00427244 (with ping)
	Local $2b5c = DllStructGetData($pStack, "2b5c") ; control
	Local $2b60 = DllStructGetData($pStack, "2b60") ; buffer 0 (hostname)
	Local $2ba0 = DllStructGetData($pStack, "2ba0") ; buffer 1
	Local $2ca4 = DllStructGetData($pStack, "2ca4") ; buffer 2
	Local $3f50 = DllStructGetData($pStack, "3f50") ; VA 0040109E
	Local $3f54 = DllStructGetData($pStack, "3f54") ; ptr PEB
	Local $3f5c = DllStructGetData($pStack, "3f5c") ; VA
	;Local $3f6c = DllStructGetData($pStack, "3f6c") ; payload size
	Local $3f78 = DllStructGetData($pStack, "3f78") ; socket descriptor
	Local $3f7c = DllStructGetData($pStack, "3f7c") ; control
	;Local $33f80 = DllStructGetData($pStack, "33f80") ; 0003002c
	;Local $33f88 = DllStructGetData($pStack, "33f88") ; VA 00402BD5

	Select
		Case $2b1c = 0x401313
		Case $2b1c = 0x401891
		Case $2b1c = 0x4018ed
		Case $2b1c = 0x402134
		Case $2b1c = 0x40207b
		Case $2b1c = 0x40217e
		Case $2b1c = 0x4023eb
		Case $2b1c = 0x401fb3
		Case $2b1c = 0x4021c7
		Case $2b1c = 0x402210
		Case $2b1c = 0x4022e9
		Case $2b1c = 0x401baf
		Case $2b1c = 0x401b6b
		Case $2b1c = 0x4024d4
		Case $2b1c = 0x40251d
		Case $2b1c = 0x402531
		Case $2b1c = 0x402545
		Case $2b1c = 0x40287f
		Case $2b1c = 0x41cc59
		Case $2b1c = 0x402b06
		Case $2b1c = 0x40272c
		Case $2b1c = 0x40275f
		Case $2b1c = 0x402792
		Case $2b1c = 0x401cc1
		Case $2b1c = 0x401e21
		Case $2b1c = 0x401e41
		Case $2b1c = 0x401ed9
		Case $2b1c = 0x401e55
		Case $2b1c = 0x402465
		Case $2b1c = 0x402498
		Case $2b1c = 0x4024ac
		Case $2b1c = 0x402b18
		Case $2b1c = 0x4024c0
		Case $2b1c = 0x402830
		Case $2b1c = 0x40251d
		Case $2b1c = 0x4026f9
		Case $2b1c = 0x40187f
		Case $2b1c = 0x401147
		Case $2b1c = 0x4015a3
		Case Else
			FileWrite($logfile, "Validation failure: 1" & @CRLF)
			Return SetError(1, 0, False)
	EndSelect

	If $2b44 <> 0x427244 Then
		FileWrite($logfile, "Validation failure: 2" & @CRLF)
		Return False
	EndIf

	If $2b5c < 0x97 Or $2b5c > 0xe8 Then
		FileWrite($logfile, "Validation failure: 3" & @CRLF)
		Return False
	EndIf

	If $2b38 - $2b3c <> 0x40 Then
		FileWrite($logfile, "Validation failure: 4" & @CRLF)
		Return False
	EndIf

	If StringLen($2b60) = 0 Then
		FileWrite($logfile, "Validation failure: 5" & @CRLF)
		Return False
	EndIf

	If $3f50 <> 0x40109e Then
		FileWrite($logfile, "Validation failure: 6" & @CRLF)
		Return False
	EndIf

	If Not ($3f54 > 0 And $3f54 < 2147483648 And Mod($3f54, 0x1000) = 0) Then
		FileWrite($logfile, "Validation failure: 7" & @CRLF)
		Return False
	EndIf

	; 0x402d38 -> connection reset
	If $3f5c <> 0x402c27 And $3f5c <> 0x402d38 Then
		FileWrite($logfile, "Validation failure: 8" & @CRLF)
		Return False
	EndIf

	If $3f78 = 0 Or ($3f78 = 4294967295 And $3f5c <> 0x402d38) Then
		FileWrite($logfile, "Validation failure: 9" & @CRLF)
		Return False
	EndIf

	If $3f7c < 0x97 Or $3f7c > 0xe8 Then
		FileWrite($logfile, "Validation failure: 10" & @CRLF)
		Return False
	EndIf

	; this check can be deactivated if targeting partial stacks
;	If $33f80 <> 0x03002c Or $33f88 <> 0x402BD5 Then
;		FileWrite($logfile, "Validation failure: 11" & @CRLF)
;		Return False
;	EndIf

	$aStruct[0] = $2b1c
	$aStruct[1] = $2b44
	$aStruct[2] = $2b5c
	$aStruct[3] = $2b60
	$aStruct[4] = $2ba0
	$aStruct[5] = $2ca4
	$aStruct[6] = $3f50
	$aStruct[7] = $3f54
	$aStruct[8] = $3f78
	$aStruct[9] = $3f7c
	$aStruct[10] = 0 ; any real value for upload will be detected later

	FileWrite($logfile, "Success validating stack." & @CRLF)
	Return True

EndFunc

Func _NwDecodeFileExplorerInit($tBuffer)
#cs
Caused by:
kernel32!GetLogicalDriveStringA

1aa0: va 0042430c
1aa8, 1ad0, 1ad8, 1adc: length + 5 (the full packet length when sending result back)
1aec: va 004095e4
1af4: a4 control
1afc: core length
1b0c: start data, each field is 4 bytes = DriveLetter + 3A + DriveType + 07
#ce
;	FileWrite($logfile, "_NwDecodeFileExplorerInit()" & @CRLF)
	FileWrite($logfile, "---- Scanning for remnants from File Explorer - Init (List Drives).." & @CRLF)

	Local $packet_len1, $packet_len2, $packet_len3, $va1, $va2, $control, $core_len, $data

	$va1 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1aa0), 1)
	$packet_len1 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1ad0), 1)
	$packet_len2 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1ad8), 1)
	$packet_len3 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1adc), 1)
	$va2 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1aec), 1)
	$control = DllStructGetData(DllStructCreate("ushort", DllStructGetPtr($tBuffer) + 0x1af4), 1)
	$core_len = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1afc), 1)

	If Not ($packet_len1 = $packet_len2 And $packet_len1 = $packet_len3 And $packet_len1 - $core_len = 5 And $packet_len1 < 0x200 And Mod($core_len, 4) = 0) Then
		FileWrite($logfile, "FE Init detection failure 1" & @CRLF)
		Return SetError(1, 0, False)
	EndIf
	If Not ($va1 = 0x42430c) Then
		FileWrite($logfile, "FE Init detection failure 2" & @CRLF)
		Return SetError(2, 0, False)
	EndIf
	If Not ($va2 = 0x4095e4) Then
		FileWrite($logfile, "FE Init detection failure 3" & @CRLF)
		Return SetError(3, 0, False)
	EndIf
	If Not ($control = 0xa4) Then
		FileWrite($logfile, "FE Init detection failure 4" & @CRLF)
		Return SetError(4, 0, False)
	EndIf

	$data = DllStructGetData(DllStructCreate("byte[" & $core_len & "]", DllStructGetPtr($tBuffer) + 0x1b0c), 1)

	_NwDriveListingDecode(StringMid($data, 3))

	Return True

EndFunc

Func _NwDriveListingDecode($hex)
	; each field is 4 bytes = DriveLetter + 3A + DriveType + 07
	Local $len = StringLen($hex)

	If $len < 8 Then
		Return SetError(1, 0, False)
	EndIf

	FileWrite($logfile, "Found Drive listing:" & @CRLF)

	Local $vol, $drivetype
	For $i = 1 To $len Step 8
		$vol = Chr(Dec(StringMid($hex, $i, 2))) & Chr(Dec(StringMid($hex, $i + 2, 2)))
		$drivetype = _NwResolveDriveType(Dec(StringMid($hex, $i + 4, 2)))
		If Dec(StringMid($hex, $i + 6, 2)) <> 7 Then
			FileWrite($logfile, "Error: Wrong field separator: " & StringMid($hex, $i + 6, 2) & @CRLF)
			Return SetError(1, 0, False)
		EndIf
		FileWrite($logfile,  $vol & " -> " & $drivetype & @CRLF)
	Next
EndFunc

Func _NwResolveDriveType($val)
	Select
		Case $val = 2
			Return "Floppy Drive"
		Case $val = 3
			Return "Fixed Drive"
		Case $val = 4
			Return "Network Drive"
		Case $val = 5
			Return "CD-ROM Drive"
		Case $val = 6
			Return "RAM Disk"
		Case Else
			Return "Unknown"
	EndSelect
EndFunc

Func _NwDecodeFileExplorerBrowse1($tBuffer)
#cs
Caused by:
kernelbase!_FindFirstFileA
kernelbase!_FindFirstFileExW
ntdll!RtlDosPathNameToRelativeNtPathName_U
ntdll!_RtlpDosPathNameToRelativeNtPathName_U
ntdll!_RtlpDosPathNameToRelativeNtPathName_Ustr
ntdll!_RtlGetFullPathName_Ustr
#ce
;	FileWrite($logfile, "_NwDecodeFileExplorerBrowse1()" & @CRLF)
	FileWrite($logfile, "---- Scanning for remnants from ntdll!NtOpenFile -> ntdll!_RtlGetFullPathName_Ustr.." & @CRLF)

	Local $len1, $len2, $len3, $addr1, $addr2, $offset_buff, $buff_check
	Select
		Case $WinVersion = "win7"
			$len1 = DllStructGetData(DllStructCreate("ushort", DllStructGetPtr($tBuffer) + 0x1e60), 1)
			$len2 = DllStructGetData(DllStructCreate("ushort", DllStructGetPtr($tBuffer) + 0x1e90), 1)
			$len3 = DllStructGetData(DllStructCreate("ushort", DllStructGetPtr($tBuffer) + 0x1f08), 1)
			$addr1 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1e48), 1)
			$addr2 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1e68), 1)
			$offset_buff = 0x1f1c
			$buff_check = DllStructGetData(DllStructCreate("wchar[4]", DllStructGetPtr($tBuffer) + 0x1f1c + $len1 - 8), 1)

		Case $WinVersion = "win81"
			$len1 = DllStructGetData(DllStructCreate("ushort", DllStructGetPtr($tBuffer) + 0x1e60), 1)
			$len2 = DllStructGetData(DllStructCreate("ushort", DllStructGetPtr($tBuffer) + 0x1e70), 1)
			$len3 = DllStructGetData(DllStructCreate("ushort", DllStructGetPtr($tBuffer) + 0x1ea8), 1)
			$addr1 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1eb4), 1)
			$addr2 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1ef4), 1)
			$offset_buff = 0x1f10
			$buff_check = DllStructGetData(DllStructCreate("wchar[4]", DllStructGetPtr($tBuffer) + 0x1f10 + $len1 - 8), 1)

		Case $WinVersion = "win10"
			$len1 = DllStructGetData(DllStructCreate("ushort", DllStructGetPtr($tBuffer) + 0x1ee4), 1)
			$len2 = DllStructGetData(DllStructCreate("ushort", DllStructGetPtr($tBuffer) + 0x1ef4), 1)
			$len3 = DllStructGetData(DllStructCreate("ushort", DllStructGetPtr($tBuffer) + 0x1f10), 1)
			$addr1 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1edc), 1)
			$addr2 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x1f00), 1)
			$offset_buff = 0x1f30
			$buff_check = DllStructGetData(DllStructCreate("wchar[4]", DllStructGetPtr($tBuffer) + 0x1f30 + $len1 - 8), 1)

	EndSelect

	Local $success = 0
	If $len1 = $len2 And $len1 = $len3 And $len1 > 0 And $len1 < 0x200 Then
		$success += 1
	EndIf
	If $addr1 = $addr2 And $addr1 > 0 And Mod($addr1, 8) = 0 Then
		$success += 1
	EndIf
	If $buff_check = "\*.*" Then
		$success += 1
	EndIf

	If $success = 3 Then
		$browse_path = DllStructGetData(DllStructCreate("wchar[" & $len1 / 2 & "]", DllStructGetPtr($tBuffer) + $offset_buff), 1)
		If StringLen($browse_path) <> $len1 / 2 Then
			; something is wrong -> reset
			FileWrite($logfile, "Error validating string: " & $browse_path & @CRLF)
			Return SetError(1, 0, False)
		Else
			FileWrite($logfile, "Found parameter: " & $browse_path & @CRLF)
		EndIf
	Else
		FileWrite($logfile, "Not found." & @CRLF)
		Return SetError(1, 0, False)
	EndIf

	Return True

EndFunc

Func _NwDecodeFileExplorerBrowse2($tBuffer)
#cs
typedef struct _FILE_BOTH_DIR_INFORMATION {
  ULONG         NextEntryOffset;
  ULONG         FileIndex;
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  LARGE_INTEGER EndOfFile;
  LARGE_INTEGER AllocationSize;
  ULONG         FileAttributes;
  ULONG         FileNameLength;
  ULONG         EaSize;
  CCHAR         ShortNameLength;
  WCHAR         ShortName[12];
  WCHAR         FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

Caused by:
kernelbase!_FindFirstFileA
kernelbase!_FindFirstFileExW
ntdll!NtQueryDirectoryFile
#ce
;	FileWrite($logfile, "_NwDecodeFileExplorerBrowse2()" & @CRLF)
	FileWrite($logfile, "---- Scanning for remnants from ntdll!NtQueryDirectoryFile -> FILE_BOTH_DIR_INFORMATION struct.." & @CRLF)

	Local $CreationTime, $LastAccessTime, $LastWriteTime, $ChangeTime, $EndOfFile, $AllocationSize, $FileAttributes, $FileNameLength, $EaSize
	Select
		Case $WinVersion = "win7"
			$CreationTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x21fc), 1)
			$LastAccessTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2204), 1)
			$LastWriteTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x220c), 1)
			$ChangeTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2214), 1)
			$EndOfFile = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x221c), 1)
			$AllocationSize = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2224), 1)
			$FileAttributes = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x222c), 1)
			$FileNameLength = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2230), 1)
			$EaSize = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2234), 1)

		Case $WinVersion = "win81"
			$CreationTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x21f0), 1)
			$LastAccessTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x21f8), 1)
			$LastWriteTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2200), 1)
			$ChangeTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2208), 1)
			$EndOfFile = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2210), 1)
			$AllocationSize = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2218), 1)
			$FileAttributes = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2220), 1)
			$FileNameLength = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2224), 1)
			$EaSize = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2228), 1)

		Case $WinVersion = "win10"
			$CreationTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x21f0), 1)
			$LastAccessTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x21f8), 1) ; overwritten
			$LastWriteTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2200), 1) ; overwritten
			$ChangeTime = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2208), 1)
			$EndOfFile = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2210), 1)
			$AllocationSize = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2218), 1)
			$FileAttributes = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2220), 1)
			$FileNameLength = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2224), 1)
			$EaSize = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2228), 1)

	EndSelect

	Local $sFileAttributes = _FileAttributes($FileAttributes)

	If $EndOfFile > 0 Or $AllocationSize > 0 Or $EaSize > 0 Or StringInStr($sFileAttributes, "directory") = 0 Then
		FileWrite($logfile, "Failure validating data." & @CRLF)
		Return SetError(1, 0, False)
	EndIf


	FileWrite($logfile, "CreationTime: " & _DecodeTimestampDecimal($CreationTime) & @CRLF)
	If $WinVersion = "win10" Then
		FileWrite($logfile, "LastAccessTime: " & $LastAccessTime & " (overwritten)" & @CRLF)
		FileWrite($logfile, "LastWriteTime: " & $LastWriteTime & " (overwritten)" & @CRLF)
	Else
		FileWrite($logfile, "LastAccessTime: " & _DecodeTimestampDecimal($LastAccessTime) & @CRLF)
		FileWrite($logfile, "LastWriteTime: " & _DecodeTimestampDecimal($LastWriteTime) & @CRLF)
	EndIf
	FileWrite($logfile, "ChangeTime: " & _DecodeTimestampDecimal($ChangeTime) & @CRLF)
	FileWrite($logfile, "EndOfFile: " & $EndOfFile & @CRLF)
	FileWrite($logfile, "AllocationSize: " & $AllocationSize & @CRLF)
	FileWrite($logfile, "FileAttributes: " & $FileAttributes & " (" & $sFileAttributes & ")" & @CRLF)
	FileWrite($logfile, "FileNameLength: " & $FileNameLength & @CRLF)
	FileWrite($logfile, "EaSize: " & $EaSize & @CRLF)

EndFunc

Func _NwDecodeFileExplorerBrowse3($tBuffer)

;	FileWrite($logfile, "_NwDecodeFileExplorerBrowse3()" & @CRLF)
	FileWrite($logfile, "---- Scanning for 004095ED remnants at 0x26fc-0x2708.." & @CRLF)

	$26fc = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x26fc), 1)
	$2704 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2704), 1)

	Select
		Case $26fc = 0x409a89
		Case $26fc = 0x409a7a
		Case $26fc = 0x409a2f
		Case $26fc = 0x40960d
		Case $26fc = 0x40962a
		Case $26fc = 0x4096db
		Case $26fc = 0x4099ac
		Case $26fc = 0x4099c6
		Case $26fc = 0x4099e3
		Case $26fc = 0x409694
		Case $26fc = 0x4096b6
		Case $26fc = 0x4097d1
		Case $26fc = 0x409858
		Case $26fc = 0x409892
		Case $26fc = 0x40995c
		Case $26fc = 0x409992
		Case $26fc = 0x4099f6
		Case Else
			FileWrite($logfile, "Not found." & @CRLF)
			Return SetError(1, 0, False)
	EndSelect

	If ($2704 <> 0xa6 And $2704 <> 0xcc) And ($26fc = 0x409a89 Or $26fc = 0x409a7a Or $26fc = 0x409a2f Or $26fc = 0x40960d)  Then
		FileWrite($logfile, "Invalid data combination at 0x26fc: " & Hex($26fc, 8) & " and 0x2704: " & Hex($2704, 8) & @CRLF)
		Return SetError(2, 0, False)
	EndIf

	FileWrite($logfile, "Control: " & Hex($2704, 2) & @CRLF)
	Return True

EndFunc

Func _NwDecodeFileExplorerBrowse4($tBuffer)
#cs
typedef struct _WIN32_FIND_DATAW {
  DWORD    dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD    nFileSizeHigh;
  DWORD    nFileSizeLow;
  DWORD    dwReserved0;
  DWORD    dwReserved1;
  WCHAR    cFileName[MAX_PATH];
  WCHAR    cAlternateFileName[14];
  DWORD    dwFileType; // Obsolete. Do not use.
  DWORD    dwCreatorType; // Obsolete. Do not use
  WORD     wFinderFlags; // Obsolete. Do not use
} WIN32_FIND_DATAW, *PWIN32_FIND_DATAW, *LPWIN32_FIND_DATAW;

Caused by:
kernel32!_FindFirstFileA
kernel32!FindNextFileA
#ce

	$tag_WIN32_FIND_DATA = "align 1;uint dwFileAttributes; " _
	&"uint64 ftCreationTime;" _
	&"uint64 ftLastAccessTime;" _
	&"uint64 ftLastWriteTime;" _
	&"uint nFileSizeHigh;" _
	&"uint nFileSizeLow;" _
	&"uint dwReserved0;" _
	&"uint dwReserved1;" _
	&"char cFileName[260];"

;	FileWrite($logfile, "_NwDecodeFileExplorerBrowse4()" & @CRLF)
	FileWrite($logfile, "---- Scanning for remnants from FindFirstFileA/FindNextFileA -> WIN32_FIND_DATAA struct at 0x2780.." & @CRLF)

	Local $dwFileAttributes, $ftCreationTime, $ftLastAccessTime, $ftLastWriteTime, $nFileSizeHigh, $nFileSizeLow, $cFileName

	$pBuf = DllStructCreate($tag_WIN32_FIND_DATA, DllStructGetPtr($tBuffer) + 0x2780)

	$dwFileAttributes = DllStructGetData($pBuf, "dwFileAttributes")
	$ftCreationTime = DllStructGetData($pBuf, "ftCreationTime")
	$ftLastAccessTime = DllStructGetData($pBuf, "ftLastAccessTime")
	$ftLastWriteTime = DllStructGetData($pBuf, "ftLastWriteTime")
	$nFileSizeHigh = DllStructGetData($pBuf, "nFileSizeHigh")
	$nFileSizeLow = DllStructGetData($pBuf, "nFileSizeLow")
	$cFileName = DllStructGetData($pBuf, "cFileName")

	If $dwFileAttributes = 0 Or StringLen($cFileName) = 0 Then
		FileWrite($logfile, "Failure validating data." & @CRLF)
		Return SetError(1, 0, False)
	EndIf
	If $ftCreationTime = 0 Or $ftLastAccessTime = 0 Or $ftLastWriteTime = 0 Then
		FileWrite($logfile, "Failure validating data." & @CRLF)
		Return SetError(2, 0, False)
	EndIf

	FileWrite($logfile, "Found an item (usually the last item alphabetic order):" & @CRLF)

	FileWrite($logfile, "FileAttributes: " & $dwFileAttributes & " (" & _FileAttributes($dwFileAttributes) & ")" & @CRLF)
	FileWrite($logfile, "CreationTime: " & _DecodeTimestampDecimal($ftCreationTime) & @CRLF)
	FileWrite($logfile, "LastAccessTime: " & _DecodeTimestampDecimal($ftLastAccessTime) & @CRLF)
	FileWrite($logfile, "LastWriteTime: " & _DecodeTimestampDecimal($ftLastWriteTime) & @CRLF)
	FileWrite($logfile, "FileSizeHigh: " & $nFileSizeHigh & @CRLF)
	FileWrite($logfile, "FileSizeLow: " & $nFileSizeLow & @CRLF)
	FileWrite($logfile, "FileName: " & $cFileName & @CRLF)

	; write a note in the cases where filename may be partially overwritten
	Select
		Case $WinVersion = "win81"
			FileWrite($logfile, "** On win81 the filename is capped at length 20." & @CRLF)
		Case $WinVersion = "win10"
			FileWrite($logfile, "** On win10 the filename is capped at length 8." & @CRLF)
	EndSelect

	Return True

EndFunc

Func _NwDecodeFileExplorerBrowse5($tBuffer)
#cs
0x1FE8E4
custom formatting of the utc converted LastWriteTime
#ce
;	FileWrite($logfile, "_NwDecodeFileExplorerBrowse5()" & @CRLF)
	FileWrite($logfile, "---- Scaninng for browsing remnants at 0x28e4" & @CRLF)

	Local $sLastWriteTime = DllStructGetData(DllStructCreate("char[20]", DllStructGetPtr($tBuffer) + 0x28e4), 1)
	If StringLen($sLastWriteTime) <> 19 Then
		FileWrite($logfile, "Validation failure" & @CRLF)
		Return SetError(1, 0, False)
	EndIf

	FileWrite($logfile, "Last items's LastWriteTime (string formatted): " & $sLastWriteTime & @CRLF)
	Return True

EndFunc

Func _NwDecodeFileExplorerBrowse6($tBuffer)
#cs
0x1FE904
custom formatting of the current/last item when iterating through FindFirstFileA/FindNextFileA
#ce
;	FileWrite($logfile, "_NwDecodeFileExplorerBrowse6()" & @CRLF)
	FileWrite($logfile, "---- Scaninng for browsing remnants at 0x2904.." & @CRLF)

	Local $bItem = DllStructGetData(DllStructCreate("byte[280]", DllStructGetPtr($tBuffer) + 0x2904), 1)
	Local $itemHex = _NetwireSpaceFix(StringMid($bItem, 3))
	Local $sItem = _HexToString($itemHex)
	If StringLen($sItem) < 19 Then
		FileWrite($logfile, "Validation failure" & @CRLF)
		Return SetError(1, 0, False)
	EndIf

	FileWrite($logfile, "Last item (string formatted): " & $sItem & @CRLF)
	Return True

EndFunc

Func _NwDecodeFileExplorerUploadDownload($tBuffer, ByRef $aStruct)

;	FileWrite($logfile, "_NwDecodeFileExplorerUpload()" & @CRLF)
	FileWrite($logfile, "---- Scaninng for remnants of file upload / download at 0x2ae8-0x2b00.." & @CRLF)

	Local $2ae8 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2ae8), 1)
	Local $2aec = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2aec), 1)
	Local $2af0 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2af0), 1)
	Local $2af4 = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x2af4), 1)
	Local $2af8 = DllStructGetData(DllStructCreate("byte[8]", DllStructGetPtr($tBuffer) + 0x2af8), 1)

	; check upload
	If ($2aec = 0x41bceb Or $2aec = 0x41bcc0) And $2af4 = 1 Then
		Local $uploadFileSize = 0
		$hex = StringMid($2af8, 3, 6)
		$uploadFileSize = Dec(_SwapEndian($hex), 2)
		$aStruct[10] = $uploadFileSize
		FileWrite($logfile, "Identified upload file size: " & Hex($uploadFileSize, 8) & @CRLF)
		Return True
	EndIf

	; check download
	If $2ae8 = 0x41c150 And $2af0 = 0 Then
		Local $downloadTimestamp
		$downloadTimestamp = DllStructGetData(DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x2af8), 1)
		FileWrite($logfile, "Identified timestamp of last downloaded file: " & _DecodeTimestampDecimal($downloadTimestamp) & @CRLF)
		Return True
	EndIf

	FileWrite($logfile, "Not found." & @CRLF)
	Return SetError(1, 0, False)

EndFunc

Func _NwDecodeCore($offset, $tBuffer, ByRef $aStruct)
	Local $pStack = DllStructCreate($tagNWSTACK, DllStructGetPtr($tBuffer))
	If @error Then
		ConsoleWrite("Error in DllStructCreate: " & @error & @CRLF)
		Return
	EndIf

	FileWrite($logfile, "-- Scanning of the core section.." & @CRLF)

	Local $2b1c = DllStructGetData($pStack, "2b1c") ; last ret address pushed on stack within main func (00401092)

	; the valid possible values
	Select
		Case $2b1c = 0x401313
		Case $2b1c = 0x401891
		Case $2b1c = 0x4018ed
		Case $2b1c = 0x402134
		Case $2b1c = 0x40207b
		Case $2b1c = 0x40217e
		Case $2b1c = 0x4023eb
		Case $2b1c = 0x401fb3
		Case $2b1c = 0x4021c7
		Case $2b1c = 0x402210
		Case $2b1c = 0x4022e9
		Case $2b1c = 0x401baf
		Case $2b1c = 0x401b6b
		Case $2b1c = 0x4024d4
		Case $2b1c = 0x40251d
		Case $2b1c = 0x402531
		Case $2b1c = 0x402545
		Case $2b1c = 0x40287f
		Case $2b1c = 0x41cc59
		Case $2b1c = 0x402b06
		Case $2b1c = 0x40272c
		Case $2b1c = 0x40275f
		Case $2b1c = 0x402792
		Case $2b1c = 0x401cc1
		Case $2b1c = 0x401e21
		Case $2b1c = 0x401e41
		Case $2b1c = 0x401ed9
		Case $2b1c = 0x401e55
		Case $2b1c = 0x402465
		Case $2b1c = 0x402498
		Case $2b1c = 0x4024ac
		Case $2b1c = 0x402b18
		Case $2b1c = 0x4024c0
		Case $2b1c = 0x402830
		Case $2b1c = 0x40251d
		Case $2b1c = 0x4026f9
		Case $2b1c = 0x40187f
		Case $2b1c = 0x401147
		Case $2b1c = 0x4015a3
		Case Else
			Return SetError(1, 0, False)
	EndSelect

	Local $2b38 = DllStructGetData($pStack, "2b38") ; ptr buffer 1
	Local $2b3c = DllStructGetData($pStack, "2b3c") ; ptr buffer 0
	Local $2b44 = DllStructGetData($pStack, "2b44") ; written when connnection is established with c2 during 9B control processing

	Local $2b5c = DllStructGetData($pStack, "2b5c") ; control
	If $2b5c < 0x97 Or $2b5c > 0xe8 Then
		FileWrite($logfile, "Validation of control code in main FAILED." & @CRLF)
		Return SetError(1, 0, False)
	EndIf

	If $2b38 - $2b3c = 0x40 Then
		FileWrite($logfile, "Validation of pointers to buffer 0 and buffer 1 is OK." & @CRLF)
		FileWrite($logfile, "VA for buffer 0: 0x" & Hex($2b3c, 8) & @CRLF)
	Else
		FileWrite($logfile, "Error in validation of pointers for buffer 0 and buffer 1." & @CRLF)
		Return SetError(1, 0, False)
	EndIf

	If $2b44 <> 0x427244 Then
		FileWrite($logfile, "The validation of main func core section FAILED." & @CRLF)
		Return SetError(1, 0, False)
	Else
		FileWrite($logfile, "The validation of main func core section is OK." & @CRLF)
	EndIf

	FileWrite($logfile, "Last control processed: " & Hex($2b5c,2) & @CRLF)

	Local $2b60 = DllStructGetData($pStack, "2b60") ; buffer 0
	If StringLen($2b60) > 0 Then
		FileWrite($logfile, "Hostname: " & $2b60 &  @CRLF)
	Else
		FileWrite($logfile, "Error resolving hostname in buffer 0." & @CRLF)
		Return SetError(1, 0, False)
	EndIf

	; buffer wipe detection
	FileWrite($logfile, "Buffer wipe detection.." & @CRLF)
	Local $2bc0 = StringMid(DllStructGetData($pStack, "2bc0"), 3) ; buffer 1 wipe check 40h
	If Not StringRegExp($2bc0, $RegExPatternHexNotNull) Then
		; is zeroed
		FileWrite($logfile, "Buffer 1: Traces of a 40h wipe." & @CRLF)
	Else
		FileWrite($logfile, "Buffer 1: No traces of a 40h wipe." & @CRLF)
	EndIf
	Local $2be0 = StringMid(DllStructGetData($pStack, "2be0"), 3) ; buffer 1 wipe check 100h
	If Not StringRegExp($2be0, $RegExPatternHexNotNull) Then
		; is zeroed
		FileWrite($logfile, "Buffer 1: Traces of a 100h wipe." & @CRLF)
	Else
		FileWrite($logfile, "Buffer 1: No traces of a 100h wipe." & @CRLF)
	EndIf
	Local $2da4 = StringMid(DllStructGetData($pStack, "2da4"), 3) ; buffer 2 wipe check 200h
	If Not StringRegExp($2da4, $RegExPatternHexNotNull) Then
		; is zeroed
		FileWrite($logfile, "Buffer 2: Traces of a 200h wipe." & @CRLF)
	Else
		FileWrite($logfile, "Buffer 2: No traces of a wipe." & @CRLF)
	EndIf
	Local $zeroedBuffer3 = False
	Local $3000 = StringMid(DllStructGetData($pStack, "3000"), 3) ; buffer 3 wipe check x
	If Not StringRegExp($3000, $RegExPatternHexNotNull) Then
		; is zeroed
		FileWrite($logfile, "Buffer 3: Traces of a wipe." & @CRLF)
		$zeroedBuffer3 = True
	Else
		FileWrite($logfile, "Buffer 3: No traces of a wipe." & @CRLF)
	EndIf
	Local $3088 = StringMid(DllStructGetData($pStack, "3088"), 3) ; buffer 3 wipe check x
	If Not StringRegExp($3088, $RegExPatternHexNotNull) Then
		; is zeroed
		FileWrite($logfile, "Buffer 3: Traces of a wipe." & @CRLF)
		$zeroedBuffer3 = True
	Else
		FileWrite($logfile, "Buffer 3: No traces of a wipe." & @CRLF)
	EndIf

	Local $2ee8 = DllStructGetData($pStack, "2ee8") ; print formatting
	Local $2ee8_trim = _NetwireSpaceFix(StringMid($2ee8, 3))
	Local $2ee8_clean = _HexToString($2ee8_trim)
	If StringLen($2ee8_clean) > 0 Then
		FileWrite($logfile, "Print formatting at 2ee8: " & $2ee8_clean &  @CRLF)
	Else
		; ok when socket descriptor not set
		If $aStruct[8] <> 4294967295 Then
			FileWrite($logfile, "Error reading pring formatting at 2ee8" & @CRLF)
			Return SetError(1, 0, False)
		EndIf
	EndIf

	; validation and wipe detection done
	; continue reading data

	Local $2ba0 = DllStructGetData($pStack, "2ba0") ; buffer 1
	If StringLen($2ba0) > 0 Then
		FileWrite($logfile, "Buffer 1: " & $2ba0 &  @CRLF)
	Else
		FileWrite($logfile, "Error reading data from buffer 1" & @CRLF)
		Return SetError(1, 0, False)
	EndIf

	Local $2ca4 = DllStructGetData($pStack, "2ca4") ; buffer 2
	Local $2ca4_trim = _NetwireSpaceFix(StringMid($2ca4, 3), True)
	Local $2ca4_clean = _HexToString($2ca4_trim)
	If StringLen($2ca4_clean) > 0 Then
		FileWrite($logfile, "Buffer 2: " & $2ca4_clean & @CRLF)
	EndIf

	Local $2f00 = DllStructGetData($pStack, "2f00") ; buffer 3
	_DecodeBuffer3($2f00)

	If Not $zeroedBuffer3 And $WinVersion = "win7" Then
		Local $3068 = DllStructGetData($pStack, "3068") ; possible c2 domain name remnant from initial connection to c2
		If StringLen($3068) > 0 Then
			FileWrite($logfile, "C2: " & $3068 & @CRLF)
		EndIf
	EndIf

	Local $socketTimestamp ; timestamp last socket event

	Select
		Case $WinVersion = "win7"
			$socketTimestamp = DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x3c4c)
			FileWrite($logfile, "Socket event timestamp: " & _DecodeTimestampDecimal(DllStructGetData($socketTimestamp, 1)) & @CRLF)
		Case $WinVersion = "win81"
			$socketTimestamp = DllStructCreate("uint64", DllStructGetPtr($tBuffer) + 0x3c28)
			FileWrite($logfile, "Socket event timestamp: " & _DecodeTimestampDecimal(DllStructGetData($socketTimestamp, 1)) & @CRLF)
		Case $WinVersion = "win10"
			FileWrite($logfile, "Socket event timestamp not present on win10" & @CRLF)
	EndSelect

	Local $3ddc = DllStructGetData($pStack, "3ddc") ; VA 40900E or 409053
	If $3ddc <> 0x40900e And $3ddc <> 0x409053 Then
		; ok with reset connections
		If $aStruct[8] <> 4294967295 Then
			FileWrite($logfile, "Error: unexpected VA at 0x3ddc: " & Hex($3ddc, 8) & @CRLF)
			Return SetError(1, 0, False)
		EndIf
	EndIf

	Local $3f50 = DllStructGetData($pStack, "3f50") ; VA 0040109E
	If $3f50 <> 0x40109e Then
		FileWrite($logfile, "Error: unexpected VA at 0x3f50: " & Hex($3f50, 8) & @CRLF)
		Return SetError(1, 0, False)
	EndIf

	Local $3f54 = DllStructGetData($pStack, "3f54") ; PEB
	If $3f54 = 0 Or $3f54 = 2147483648 Or Mod($3f54, 0x1000) > 0 Then
		FileWrite($logfile, "Error: Bad PEB value at 0x3f54: 0x" & Hex($3f54, 8) & @CRLF)
		Return SetError(1, 0, False)
	EndIf

	Local $3f6c = DllStructGetData($pStack, "3f6c") ; payload size

	Local $3f78 = DllStructGetData($pStack, "3f78") ; socket descriptor
	If $3f78 = 0 Then
		FileWrite($logfile, "Error: socket descriptor at 0x3f78 was null: " & @CRLF)
		Return SetError(1, 0, False)
	EndIf
	FileWrite($logfile, "Socket descriptor at 3f78: " & Hex($3f78, 8) & @CRLF)
	If $3f78 = 4294967295 Then
		FileWrite($logfile, "The socket descriptor indicates that connection to c2 has been reset." & @CRLF)
	EndIf

	Local $3f7c = DllStructGetData($pStack, "3f7c") ; control
	If $3f7c < 0x97 Or $3f7c > 0xe8 Then
		FileWrite($logfile, "Validation of control code in main FAILED." & @CRLF)
		Return SetError(1, 0, False)
	EndIf
	; check if controls differ
	If $2b5c = $3f7c Then
		FileWrite($logfile, "Both control codes (0x2b5c and 0x3f7c) match: " & Hex($3f7c,2) & @CRLF)
	Else
		FileWrite($logfile, "A control not yet processed has been detected as values at 0x2b5c and 0x3f7c differ." & @CRLF)
		FileWrite($logfile, "Control at 0x2b5c: " & Hex($2b5c,2) & @CRLF)
		FileWrite($logfile, "Control at 0x3f7c: " & Hex($3f7c,2) & @CRLF)
	EndIf

	If $3f7c = 0x97 And $3f6c > 0 Then
		FileWrite($logfile, "Error: Invalid payload size for ping: 0x" & Hex($3f6c, 8) & @CRLF)
		Return SetError(1, 0, False)
	EndIf
	If $3f6c > 0x2ffff Then
		FileWrite($logfile, "Error: Invalid payload size: 0x" & Hex($3f6c, 8) & @CRLF)
		Return SetError(1, 0, False)
	EndIf
	FileWrite($logfile, "Size of the payload for the current control: 0x" & Hex($3f6c, 8) & @CRLF)

	; the raw payload is dumped to disk separately, here we extract text + possible slack
	Local $3f7d = DllStructGetData($pStack, "3f7d") ; payload
	;Local $3f7d_trim = _NetwireSpaceFix(StringMid($3f7d, 3), True)
	Local $3f7d_trim = _NetwirePayloadAndSlack(StringMid($3f7d, 3))
	Local $3f7d_clean = _HexToString($3f7d_trim)
	If StringLen($3f7d_clean) > 0 Then
		FileWrite($logfile, "Text formatted payload including slack: " & @CRLF)
		FileWrite($logfile, $3f7d_clean & @CRLF)
	EndIf

	Local $33f80 = DllStructGetData($pStack, "33f80") ; size 0003002c
	Local $33f88 = DllStructGetData($pStack, "33f88") ; VA 00402BD5

	Local $stackEndValidationFailure = 0
	If $33f80 <> 0x03002c Or $33f88 <> 0x402BD5 Then
		FileWrite($logfile, "End of stack validation 1 FAILED." & @CRLF)
		$stackEndValidationFailure += 1
	Else
		FileWrite($logfile, "End of stack validation 1 OK." & @CRLF)
	EndIf

	Local $endPEB
	Select
		Case $WinVersion = "win7"
			$endPEB = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x33ff8), 1)
		Case $WinVersion = "win81"
			$endPEB = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x34000), 1)
		Case $WinVersion = "win10"
			$endPEB = DllStructGetData(DllStructCreate("uint", DllStructGetPtr($tBuffer) + 0x34010), 1)
	EndSelect

	If $3f54 = $endPEB Then
		FileWrite($logfile, "End of stack validation 2 OK." & @CRLF)
		FileWrite($logfile, "PEB match in upper two levels: 0x" & Hex($3f54, 8) & @CRLF)
	Else
		FileWrite($logfile, "End of stack validation 2 FAILED." & @CRLF)
		$stackEndValidationFailure += 1
	EndIf

	If $stackEndValidationFailure > 0 Then
		FileWrite($logfile, "WARNING: The end of stack validation had failures. Some of the last bytes are likely overwritten." & @CRLF)
	Else
		FileWrite($logfile, "The full stack is validated." & @CRLF)
	EndIf

	; the complete raw payload
	Local $payloadFile = $OutPutPath & "\" & Hex($offset, 16) & "_raw_payload_section.bin"
	Local $hPayloadFile = _WinAPI_CreateFile("\\.\" & $payloadFile, 3, 6, 7)
	Local $nbytes
	If Not _WinAPI_WriteFile($hPayloadFile, DllStructGetPtr($pStack, "3f7d"), 0x2ffff, $nbytes) Then
		ConsoleWrite("Error in WriteFile: " & _WinAPI_GetLastErrorMessage() & @CRLF)
		Exit(1)
	EndIf
	_WinAPI_CloseHandle($hPayloadFile)

	; the core upload if detected
	Local $uploadFileSize = $aStruct[10]
	If $uploadFileSize > 0 And $uploadFileSize < 0x2ffff Then
		Local $uploadFile = $OutPutPath & "\" & Hex($offset, 16) & "_last_upload.bin"
		Local $hUploadFile = _WinAPI_CreateFile("\\.\" & $uploadFile, 3, 6, 7)
		If Not _WinAPI_WriteFile($hUploadFile, DllStructGetPtr($pStack, "3f7d")+1, $uploadFileSize, $nbytes) Then
			ConsoleWrite("Error in WriteFile: " & _WinAPI_GetLastErrorMessage() & @CRLF)
			Exit(1)
		EndIf
		_WinAPI_CloseHandle($hUploadFile)
	EndIf

EndFunc

Func _AnalyzeOffset($hFile, $offset, $size)
	Local $nbytes
	If $size < 1 Then
		ConsoleWrite("Nothing to do. Size: " & $size & @CRLF)
		Return
	EndIf

	Local $tBuffer = DllStructCreate("byte[" & $size & "]")
	_WinAPI_SetFilePointerEx($hFile, $offset, $FILE_BEGIN)
	Local $read = _WinAPI_ReadFile($hFile, DllStructGetPtr($tBuffer), DllStructGetSize($tBuffer), $nbytes)
	If $read = 0 Then
		ConsoleWrite("ReadFile: " & _WinAPI_GetLastErrorMessage() & @CRLF)
		Return SetError(1)
	EndIf

	Local $aStruct[11]

	$isHealthy = _PreValidation($offset, $tBuffer, $aStruct)

	; check if unhealthy stacks are to be dumped
	If Not $isHealthy Or @error Then
		If $dumpAll Then
			_DumpStack($tBuffer, $offset, $isHealthy)
		EndIf
		Return
	EndIf

	_DumpStack($tBuffer, $offset, $isHealthy)

	; File Explorer initialization - drive listing
	_NwDecodeFileExplorerInit($tBuffer)

	; low level stuff from ntdll
	If _NwDecodeFileExplorerBrowse1($tBuffer) And Not @error Then
		_NwDecodeFileExplorerBrowse2($tBuffer)
	EndIf

	; medium level 004095ED (a6 or cc)
	If _NwDecodeFileExplorerBrowse3($tBuffer) And Not @error Then
		If _NwDecodeFileExplorerBrowse4($tBuffer) And Not @error Then
			If $aStruct[2] = 0xa6 Or $aStruct[2] = 0xcc Then
				_NwDecodeFileExplorerBrowse5($tBuffer)
				_NwDecodeFileExplorerBrowse6($tBuffer)
			EndIf
		EndIf
	EndIf

	; 0x2ae8 - 0x2b00
	_NwDecodeFileExplorerUploadDownload($tBuffer, $aStruct)

	; remaining higher level and netwire core specific
	_NwDecodeCore($offset, $tBuffer, $aStruct)

	$aStruct = 0
EndFunc

Func _DumpStack($tBuffer, $offset, $isHealthy)

	Local $nbytes, $OutputFile
	If $isHealthy Then
		$OutputFile = $OutPutPath & "\" & Hex($offset, 16) & "_stack_aligned.bin"
	Else
		$OutputFile = $OutPutPath & "\" & Hex($offset, 16) & "_stack_aligned_unhealthy.bin"
	EndIf
	Local $hOutFile = _WinAPI_CreateFile("\\.\" & $OutputFile, 3, 6, 7)
	If Not _WinAPI_WriteFile($hOutFile, DllStructGetPtr($tBuffer), DllStructGetSize($tBuffer), $nbytes) Then
		ConsoleWrite("Error in WriteFile: " & _WinAPI_GetLastErrorMessage() & @CRLF)
		Exit(1)
	EndIf
	_WinAPI_CloseHandle($hOutFile)
EndFunc

Func _GetFilenameFromPath($FileNamePath)
	$stringlength = StringLen($FileNamePath)
	If $stringlength = 0 Then Return SetError(1,0,0)
	$TmpOffset = StringInStr($FileNamePath, "\", 1, -1)
	If $TmpOffset = 0 Then Return $FileNamePath
	Return StringMid($FileNamePath,$TmpOffset+1)
EndFunc

Func _GetPathFromFilenamePath($FileNamePath)
	$stringlength = StringLen($FileNamePath)
	If $stringlength = 0 Then SetError(1)
	$TmpOffset = StringInStr($FileNamePath, "\", 1, -1)
	If $TmpOffset = 0 Then Return $FileNamePath
	Return StringMid($FileNamePath, 1, $TmpOffset-1)
EndFunc

Func _FixWindowsFilename($input)
	$input = StringReplace($input, "/", "")
	$input = StringReplace($input, "\", "")
	$input = StringReplace($input, ":", "")
	$input = StringReplace($input, "*", "")
	$input = StringReplace($input, "?", "")
	$input = StringReplace($input, '"', "")
	$input = StringReplace($input, "<", "")
	$input = StringReplace($input, ">", "")
	Return $input
EndFunc

Func _SwapEndian($iHex)
	Return StringMid(Binary(Dec($iHex,2)),3, StringLen($iHex))
EndFunc

Func _HexEncode($bInput)
    Local $tInput = DllStructCreate("byte[" & BinaryLen($bInput) & "]")
    DllStructSetData($tInput, 1, $bInput)
    Local $a_iCall = DllCall("crypt32.dll", "int", "CryptBinaryToString", _
            "ptr", DllStructGetPtr($tInput), _
            "dword", DllStructGetSize($tInput), _
            "dword", 11, _
            "ptr", 0, _
            "dword*", 0)

    If @error Or Not $a_iCall[0] Then
        Return SetError(1, 0, "")
    EndIf
    Local $iSize = $a_iCall[5]
    Local $tOut = DllStructCreate("char[" & $iSize & "]")
    $a_iCall = DllCall("crypt32.dll", "int", "CryptBinaryToString", _
            "ptr", DllStructGetPtr($tInput), _
            "dword", DllStructGetSize($tInput), _
            "dword", 11, _
            "ptr", DllStructGetPtr($tOut), _
            "dword*", $iSize)
    If @error Or Not $a_iCall[0] Then
        Return SetError(2, 0, "")
    EndIf
    Return SetError(0, 0, DllStructGetData($tOut, 1))
EndFunc

Func _DebugOut($text, $var="")
   If $var Then $var = _HexEncode($var) & @CRLF
   $text &= @CRLF & $var
   ConsoleWrite($text)
   If $logfile Then FileWrite($logfile, $text)
EndFunc


Func _HexToRegExFormat($hex)
	$len = StringLen($hex)
	If $len < 2 Then
		Return SetError(1, 0, 0)
	EndIf
	$ret = ""
	For $i = 1 To $len Step 2
		$ret &= "\x" & StringMid($hex, $i, 2)
	Next
	Return $ret
EndFunc

Func _Signature2Array_v2($FilePath, ByRef $arr, $TargetString, $RegexString)

	_DebugOut("Using input: " & _GetFilenameFromPath($FilePath) & @CRLF)
	$sPSScript = '"' & $sPSScript & '"'

	Local $sCMD = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File " & $sPSScript & " -hex " & $RegexString & " -filepath " & '"' & $FilePath & '"'

	Local $pid = Run($sCMD, @SystemDir, @SW_HIDE, $STDIN_CHILD + $STDOUT_CHILD + $STDERR_CHILD)
	If @error Then
		_DebugOut("Error: Could not execute external script" & @CRLF)
		Exit
	EndIf

	StdinWrite($pid)
	Local $AllOutput = "", $sOutput = ""
	Local $hTimer = TimerInit()
	While 1
		$sOutput = StdoutRead($pid)
		If @error Then ExitLoop
		If $sOutput <> "" Then $AllOutput &= $sOutput
		If Not ProcessExists($pid) Then ExitLoop
		; exit the loop if processing is +100 min
		If TimerDiff($hTimer) > 6000000 Then ExitLoop
	WEnd

;	ConsoleWrite("$AllOutput" & @CRLF)
;	ConsoleWrite($AllOutput & @CRLF)

	If StringInStr($AllOutput, "Error") Then
		_DebugOut("Error: Something went wrong in the parsing of input" & @CRLF)
		_DebugOut($AllOutput & @CRLF)
		Return 0
	EndIf


	Local $OutputArray = StringSplit($AllOutput, @CRLF)
	;_ArrayDisplay($OutputArray, "$OutputArray")

	Local $counter = 0
	Local $currentArraySize = UBound($arr)
	ReDim $arr[$currentArraySize + $OutputArray[0]][2]
	For $i = 1 To $OutputArray[0]
		If $OutputArray[$i] = "" Then
			ContinueLoop
		EndIf
		If StringLeft($OutputArray[$i], 2) <> "0x" Then
			ContinueLoop
		EndIf
		If StringLen($OutputArray[$i]) <> 18 Then
			ContinueLoop
		EndIf
		$arr[$currentArraySize + $counter][0] = Number($OutputArray[$i])
		$arr[$currentArraySize + $counter][1] = $TargetString
		$counter += 1
	Next

	ReDim $arr[$currentArraySize + $counter][2]
;	_ArrayDisplay($arr, "$arr")
	Return $counter
EndFunc

Func _NetwireSpaceFix($hex, $doslack=False)
	Local $len = StringLen($hex)
	If $len < 2 Then
		Return SetError(1, 0, 0)
	EndIf
	Local $ret = "", $dec = 0, $max = 512
	For $i = 1 To $len Step 2
		If $i > $max Then
			;$sTextInfo &= ";string was chopped"
			ExitLoop
		EndIf
		$dec = Dec(StringMid($hex, $i, 2))
		Select
			Case $dec = 0 And $doslack
				If Dec(StringMid($hex, $i+2, 2)) = 0 Then
					ExitLoop
				EndIf
				; add {0} as null replacement to differentiate on remnants
				$ret &= "7B307D"
			Case $dec = 2 Or $dec = 3 Or $dec = 4 Or $dec = 5 Or $dec = 6
				$ret &= ""
			Case $dec = 7
				If Dec(StringMid($hex, $i+2, 2)) = 0 Then
					ExitLoop
				EndIf
				$ret &= "20"
			Case $dec >= 32 And $dec < 127
				If $dec = $ade Then
					; replace char if equal to separator
					$ret &= "20"
				Else
					$ret &= StringMid($hex, $i, 2)
				EndIf
			Case Else
				ExitLoop
		EndSelect
	Next
	Return $ret
EndFunc

Func _NetwirePayloadAndSlack($hex, $max=256)
	Local $len = StringLen($hex)
	If $len < 2 Then
		Return SetError(1, 0, 0)
	EndIf
	Local $ret = "", $dec = 0
	For $i = 1 To $len Step 2
		If $i >= $max Then
			ExitLoop
		EndIf
		$dec = Dec(StringMid($hex, $i, 2))
		Select
			Case $dec = 0
				If $i < $len - 6 And StringMid($hex, $i + 2, 4) = "0000" Then
					ExitLoop
				EndIf
				$ret &= "7B307D"
			Case $dec >= 32 And $dec < 127
				$ret &= StringMid($hex, $i, 2)
			Case Else
				$ret &= "20"
		EndSelect
	Next

	; write to log
	Local $pData = DllStructCreate("byte[" & Int(($i - 1) / 2) & "]")
	DllStructSetData($pData, 1, "0x" & StringMid($hex, 1, $i - 1))
	FileWrite($logfile, "First " & DllStructGetSize($pData) & " bytes of raw payload:" & @CRLF)
	FileWrite($logfile, _HexEncode(DllStructGetData($pData, 1)))

	Return $ret
EndFunc

Func _DecodeTimestampDecimal0($ulTime)
	Local $sTime = _WinTime_UTCFileTimeFormat($ulTime - $tDelta, $DateTimeFormat, $TimestampPrecision)
	If @error Then
		$sTime = $TimestampErrorVal
	EndIf
	Return $sTime
EndFunc

Func _DecodeTimestampDecimal($ulTime)
	;$TheTime = Hex($TheTime,16)
	$sTime_tmp = _WinTime_UTCFileTimeToLocalFileTime("0x" & Hex($ulTime,16))
	$sTime = _WinTime_UTCFileTimeFormat($ulTime - $tDelta, $DateTimeFormat, $TimestampPrecision)
	If @error Then
		$sTime = $TimestampErrorVal
	ElseIf $TimestampPrecision = 3 Then
		$sTime = $sTime & $PrecisionSeparator2 & _FillZero(StringRight($sTime_tmp, 4))
	EndIf
	Return $sTime
EndFunc

Func _FillZero($inp)
	Local $inplen, $out, $tmp = ""
	$inplen = StringLen($inp)
	For $i = 1 To 4 - $inplen
		$tmp &= "0"
	Next
	$out = $tmp & $inp
	Return $out
EndFunc

Func _DecodeBuffer3($2f00)
	Local $b1 = Dec(StringMid($2f00, 3, 2))
	Select
		Case $b1 = 0
			; wiped
			FileWrite($logfile, "Buffer 3: zeroed" & @CRLF)

		Case $b1 > 0 And $b1 < 6
			; platform code ok
			FileWrite($logfile, "Buffer 3: Host details set during initial connection:" & @CRLF)
			_ParseHostInitDetails(StringMid($2f00, 3))

		Case $b1 >= 0x30 And $b1 < 0x40
			; various commands may have left this..
			$string = _ExtractAnsiStringFromHex(StringMid($2f00, 3))
			FileWrite($logfile, "Buffer 3: " & $string & @CRLF)

		Case Else
			;string
			$string = _ExtractAnsiStringFromHex(StringMid($2f00, 3))
			FileWrite($logfile, "Buffer 3: " & $string & @CRLF)

	EndSelect
EndFunc

Func _GetPlatform($id)
	; value as translated on c2 and displayed in ui
	Select
		Case $id = 1
			Return "Windows"
		Case $id = 2
			Return "GNU/Linux"
		Case $id = 3
			Return "Solaris"
		Case $id = 4
			Return "Mac OS X"
		Case $id = 5
			Return "Android"
		Case Else
			Return "UNKNOWN"
	EndSelect
EndFunc

Func _GetOSVersion($val)
	; value as translated on c2 and displayed in ui
	Select
		Case $val = 0
			Return "Windows"
		Case $val = 1
			Return "Windows 32s"
		Case $val = 2
			Return "Windows 95"
		Case $val = 3
			Return "Windows 95 SR2"
		Case $val = 4
			Return "Windows 98"
		Case $val = 5
			Return "Windows 98 SE"
		Case $val = 6
			Return "Windows Me"
		Case $val = 7
			Return "Windows NT 3.51"
		Case $val = 8
			Return "Windows NT 4.0"
		Case $val = 9
			Return "Windows NT 4.0 Server"
		Case $val = 10
			Return "Windows 2000"
		Case $val = 11
			Return "Windows XP"
		Case $val = 12
			Return "Windows XP Professional x64"
		Case $val = 13
			Return "Windows Home Server"
		Case $val = 14
			Return "Windows Server 2003"
		Case $val = 15
			Return "Windows Server 2003 R2"
		Case $val = 16
			Return "Windows Vista"
		Case $val = 17
			Return "Windows Server 2008"
		Case $val = 18
			Return "Windows 7"
		Case $val = 19
			Return "Windows Server 2008 R2"
		Case $val = 20
			Return "Windows 8"
		Case $val = 21
			Return "Windows 8.1"
		Case $val = 22
			Return "Windows Server 2012"
		Case $val = 23
			Return "Windows 10"
		Case $val = 24
			Return "Windows Server 2012 R2"
		Case $val = 25
			Return "Windows Server 2016"
		Case Else
			Return "UNKNOWN"
	EndSelect
EndFunc

Func _ParseHostInitDetails($hex)
	; decode of all data sent on initial connect to c2, and with values as displayed in ui
	; the NwVersion is formatted in such a way: The bytes (3031303736313030) are converted to characters (01076100) -> 1.7a
	Local $b1 = Dec(StringMid($hex, 1, 2))
	Local $aDetailsHex[4]
	Local $counter = 0
	For $i = 3 To StringLen($hex) Step 2
		If StringMid($hex, $i, 2) = "00" Then
			ExitLoop
		EndIf
		If StringMid($hex, $i, 2) = "07" Then
			$counter += 1
			ContinueLoop
		EndIf
		$aDetailsHex[$counter] &= StringMid($hex, $i, 2)
	Next
	Local $sPlatform = _GetPlatform($b1)
	Local $NwVersion = StringLen($aDetailsHex[0]) > 0 ? _HexToString($aDetailsHex[0]) : ""
	Local $UsernameAndHostname = StringLen($aDetailsHex[1]) > 0 ? _HexToString($aDetailsHex[1]) : ""
	Local $OSVersion = StringLen($aDetailsHex[2]) > 0 ? _HexToString($aDetailsHex[2]) : ""
	Local $sOSVersion = _GetOSVersion(Number($OSVersion))
	Local $InstallDate = StringLen($aDetailsHex[3]) > 0 ? _HexToString($aDetailsHex[3]) : "" ; missing in 1.7

	FileWrite($logfile, "	Platform: " & $sPlatform & @CRLF)
	FileWrite($logfile, "	NwVersion: " & $NwVersion & @CRLF)
	FileWrite($logfile, "	UsernameAndHostname: " & $UsernameAndHostname & @CRLF)
	FileWrite($logfile, "	sOSVersion: " & $sOSVersion & @CRLF)
	FileWrite($logfile, "	InstallDate: " & $InstallDate & @CRLF)
EndFunc

Func _ExtractAnsiStringFromHex($hex)
	Local $ret=""
	For $i = 1 To StringLen($hex) Step 2
		If Dec(StringMid($hex, $i, 2)) < 32 Then
			ExitLoop
		EndIf
		$ret &= StringMid($hex, $i, 2)
	Next
	Return _HexToString($ret)
EndFunc

Func _FileAttributes($iVal)
	Local $sOutput = ""
	If BitAND($iVal, 0x0001) Then $sOutput &= 'read_only+'
	If BitAND($iVal, 0x0002) Then $sOutput &= 'hidden+'
	If BitAND($iVal, 0x0004) Then $sOutput &= 'system+'
	If BitAND($iVal, 0x0010) Then $sOutput &= 'directory+'
	If BitAND($iVal, 0x0020) Then $sOutput &= 'archive+'
	If BitAND($iVal, 0x0040) Then $sOutput &= 'device+'
	If BitAND($iVal, 0x0080) Then $sOutput &= 'normal+'
	If BitAND($iVal, 0x0100) Then $sOutput &= 'temporary+'
	If BitAND($iVal, 0x0200) Then $sOutput &= 'sparse_file+'
	If BitAND($iVal, 0x0400) Then $sOutput &= 'reparse_point+'
	If BitAND($iVal, 0x0800) Then $sOutput &= 'compressed+'
	If BitAND($iVal, 0x1000) Then $sOutput &= 'offline+'
	If BitAND($iVal, 0x2000) Then $sOutput &= 'not_content_indexed+'
	If BitAND($iVal, 0x4000) Then $sOutput &= 'encrypted+'
	If BitAND($iVal, 0x8000) Then $sOutput &= 'integrity_stream+'
	If BitAND($iVal, 0x10000) Then $sOutput &= 'virtual+'
	If BitAND($iVal, 0x20000) Then $sOutput &= 'no_scrub_data+'
	If BitAND($iVal, 0x40000) Then $sOutput &= 'ea+'
	If BitAND($iVal, 0x80000) Then $sOutput &= 'pinned+'
	If BitAND($iVal, 0x100000) Then $sOutput &= 'unpinned+'
	If BitAND($iVal, 0x400000) Then $sOutput &= 'recall_on_data_access+'
	If BitAND($iVal, 0x10000000) Then $sOutput &= 'directory+'
	If BitAND($iVal, 0x20000000) Then $sOutput &= 'index_view+' ; strictly_sequencial?
	$sOutput = StringTrimRight($sOutput, 1)
	Return $sOutput
EndFunc

Func _GetInputParams()
	Local $TmpInputFile, $TmpHostname, $TmpWinVersion
	For $i = 1 To $cmdline[0]
		;ConsoleWrite("Param " & $i & ": " & $cmdline[$i] & @CRLF)
		If StringLeft($cmdline[$i],2) = "/?" Or StringLeft($cmdline[$i],2) = "-?" Or StringLeft($cmdline[$i],2) = "-h" Then _PrintHelp()
		If StringLeft($cmdline[$i],7) = "/Input:" Then $TmpInputFile = StringMid($cmdline[$i],8)
		;If StringLeft($cmdline[$i],12) = "/OutputPath:" Then $TmpOutputPath = StringMid($cmdline[$i],13)
		If StringLeft($cmdline[$i],10) = "/Hostname:" Then $TmpHostname = StringMid($cmdline[$i],11)
		If StringLeft($cmdline[$i],12) = "/WinVersion:" Then $TmpWinVersion = StringMid($cmdline[$i],13)
		If $cmdline[$i] = "/DumpAll" Then $dumpAll = True
	Next
#cs
	If StringLen($TmpOutputPath) > 0 Then
		If FileExists($TmpOutputPath) Then
			$OutPutPath = $TmpOutputPath
		Else
			ConsoleWrite("Warning: The specified Output path could not be found: " & $TmpOutputPath & @CRLF)
			ConsoleWrite("Relocating output to current directory: " & @ScriptDir & @CRLF)
			$OutPutPath = @ScriptDir
		EndIf
	EndIf
#ce
	If StringLen($TmpInputFile) > 0 Then
		If FileExists($TmpInputFile) = 0 Then
			ConsoleWrite("Error: Input not found: " & $TmpInputFile & @CRLF)
			Exit
		EndIf
		$targetFile = $TmpInputFile
	Else
		ConsoleWrite("Error: Missing input" & @CRLF)
		Exit
	EndIf

	If StringLen($TmpHostname) = 0 Then
		ConsoleWrite("Error: Missing hostname" & @CRLF)
		Exit
	Else
		$targetHostname = $TmpHostname
	EndIf

	If StringLen($TmpWinVersion) > 0 Then
		Select
			Case $TmpWinVersion = "win7"
				$winVersion = $TmpWinVersion

			Case $TmpWinVersion = "win81"
				$winVersion = $TmpWinVersion

			Case $TmpWinVersion = "win10"
				$winVersion = $TmpWinVersion

			Case Else
				ConsoleWrite("Error: Invalid winversion: " & $TmpWinVersion & @CRLF)
				Exit
		EndSelect
	Else
		ConsoleWrite("Error: Missing winversion" & @CRLF)
		Exit
	EndIf

EndFunc

Func _PrintHelp()
	ConsoleWrite("Syntax:" & @CRLF)
	ConsoleWrite("nwstacks /Input: /WinVersion: /Hostname: /DumpAll" & @CRLF)
	ConsoleWrite("   Input: Full path to the input file to parse" & @CRLF)
	ConsoleWrite("   WinVersion: Valid values (win7, win81, win10)." & @CRLF)
	ConsoleWrite("   Hostname: The hostname of computer where input is from." & @CRLF)
	ConsoleWrite("   DumpAll: Optional switch to dump also the unhealthy stacks. Default is off." & @CRLF)
	ConsoleWrite("Examples:" & @CRLF)
	ConsoleWrite("nwstacks.exe /Input:D:\temp\pagefile.sys /WinVersion:win7 /Hostname:sample-PC /DumpAll" & @CRLF)
	ConsoleWrite("nwstacks.exe /Input:D:\temp\pagefile.sys /WinVersion:win81 /Hostname:sample-PC" & @CRLF)
	Exit
EndFunc