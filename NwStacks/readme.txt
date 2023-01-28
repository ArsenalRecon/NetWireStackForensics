Tool for scanning and analyzing NetWire 1.7 stacks.

Supporting stacks from:
* Windows 7 32-bit
* Windows 7 64-bit
* Windows 8.1 64-bit
* Windows 10 64-bit

Requirements
The scan mechanism uses a powershell script, and needs to have execution of scripts enabled. This can be achieve with a command such as;
powershell Set-ExecutionPolicy unrestricted

Builds
Builds are available at https://github.com/ArsenalRecon/NetWireStackForensics/releases

Syntax:
nwstacks /Input: /WinVersion: /Hostname: /DumpAll
* Input: Full path to the input file to parse.
* WinVersion: Valid values (win7, win81, win10).
* Hostname: The hostname of computer where input is from.
* DumpAll: Optional switch to dump also the unhealthy stacks that failed validation. Deactivated by default.

Examples:
nwstacks.exe /Input:D:\temp\pagefile.sys /WinVersion:win7 /Hostname:sample-PC /DumpAll
nwstacks.exe /Input:D:\temp\pagefile.sys /WinVersion:win81 /Hostname:sample-PC

Output:
A folder named NwStacks_[timestamp] is create per execution. There will be a logfile with decode information from all signature hits, and additional output per stack that is found.
* nwstacks.log: The main log file with all decode information.
* [offset]_raw_payload_section.bin
* [offset]_stack_aligned.bin
* [offset]_last_upload.bin