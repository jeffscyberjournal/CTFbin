# Skynet

## Q1 What is Miles password for his emails?

## Quick nmap scan:
```
nmap -sC -sV -Pn <targetIP>


```
```
root@ip-10-144-94-86:~# smbclient -L //10.144.136.168
Password for [WORKGROUP\root]:

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	anonymous       Disk      Skynet Anonymous Share
	milesdyson      Disk      Miles Dyson Personal Share
	IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))
root@ip-10-144-94-86:~#
```
