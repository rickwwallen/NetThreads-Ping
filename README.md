Netthreads-Ping
==========================
This code utilizes a NetFPGA compiler project NetThreads. This compiler is required for the usage of the code in this
project. Compiling and loading the code is based upon the NetThreads project and instructions can be seen via site
https://github.com/NetFPGA/netfpga/wiki/NetThreads

This is my version of the ping program. I have gotten this to work on netfpga-base 3.0.1 confirming that the Netthreads project works with a newer than 2.0 CPCI. Also, if you decide upon creating your own project be sure to include the ARP sections of code. You will need to change the IP addresses and MAC address to your device.  

File List:

	./
	|-- Makefile
	|-- README.md
	`-- process.c

