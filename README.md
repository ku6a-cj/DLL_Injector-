# DLL_Injector-
Program that inject a Dll to a selected Process

How does it work?

Steps:
1) Obtain a handle to kernel32.dll
2) Get adress of LoadLibraryA
3) Scan for process that we are lokkong for to inject our Dll
4) Obtain handle to a process
5) Suspend process
6) Alocate memory in process
7) Save Dll to a process
8) Create remote thread that will "run" our Dll in a proces
9) Resume process
10) Clear memory 
