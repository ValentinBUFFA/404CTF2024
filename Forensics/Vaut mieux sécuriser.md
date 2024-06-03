
Lors d'une compétition de lancer de poids, un athlète laisse son ordinateur allumé avec sa session ouverte. Cependant, une personne a utilisé son ordinateur et, a vraisemblablement fait des cachoteries. Nous vous mettons à disposition le dump de la RAM de l'ordinateur après l'incident.  
Investiguez ce dump mémoire pour comprendre ce qu'il s'est passé.

---

La deuxième partie du flag est le **nom d'une certaine tâche**.  
Les deux parties sont séparées d'un tiret "-". Par exemple si le flag de la première partie est "flag1" et celui de la deuxième partie est "flag2". Le réel flag du challenge sera 404CTF{flag1-flag2}

----

RAM dump => **volatilty**

`vol -f memory.dmp cmdline`

Powershell (PID 4852) spawned a conhost.exe, it might be malware

this file is opened
```
0xd50ebb9b2bf0	\Windows\System32\WindowsPowerShell\v1.0\Modules\ScheduledTasks\PS_ClusteredScheduledTask_v1.0.cdxml	216
```

We might dump
```
0xd50ebbb3cef0	\Windows\System32\backgroundTaskHost.exe	216
```
to get the scheduled tasks

malfind lists powershell.exe a lot
```
4852	powershell.exe	0x154e9670000	0x154e967ffff	VadS	PAGE_EXECUTE_READWRITE	8	1	Disabled	
00 00 00 00 00 00 00 00	........
f0 76 78 9c 2c 40 00 01	.vx.,@..
ee ff ee ff 02 00 00 00	........
20 01 67 e9 54 01 00 00	..g.T...
20 01 67 e9 54 01 00 00	..g.T...
00 00 67 e9 54 01 00 00	..g.T...
00 00 67 e9 54 01 00 00	..g.T...
0f 00 00 00 00 00 00 00	........	
0x154e9670000:	add	byte ptr [rax], al
0x154e9670002:	add	byte ptr [rax], al
0x154e9670004:	add	byte ptr [rax], al
0x154e9670006:	add	byte ptr [rax], al
4852	powershell.exe	0x154d11b0000	0x154d11bffff	VadS	PAGE_EXECUTE_READWRITE	2	1	Disabled	
00 00 00 00 00 00 00 00	........
23 92 93 30 5a 05 00 01	#..0Z...
ee ff ee ff 02 00 00 00	........
20 01 1b d1 54 01 00 00	....T...
20 01 1b d1 54 01 00 00	....T...
00 00 1b d1 54 01 00 00	....T...
00 00 1b d1 54 01 00 00	....T...
0f 00 00 00 00 00 00 00	........	
0x154d11b0000:	add	byte ptr [rax], al
0x154d11b0002:	add	byte ptr [rax], al
0x154d11b0004:	add	byte ptr [rax], al
0x154d11b0006:	add	byte ptr [rax], al
0x154d11b0008:	and	edx, dword ptr [rdx + 0x55a3093]
0x154d11b000e:	add	byte ptr [rcx], al
0x154d11b0010:	out	dx, al
4852	powershell.exe	0x154e96d0000	0x154e96d6fff	VadS	PAGE_EXECUTE_READWRITE	1	1	Disabled	
00 00 00 00 00 00 00 00	........
a0 79 67 e9 54 01 00 00	.yg.T...
a0 79 67 e9 54 01 00 00	.yg.T...
00 00 67 e9 54 01 00 00	..g.T...
b0 0d 6d e9 54 01 00 00	..m.T...
00 10 6d e9 54 01 00 00	..m.T...
00 70 6d e9 54 01 00 00	.pm.T...
01 00 00 00 00 00 00 00	........	
0x154e96d0000:	add	byte ptr [rax], al
0x154e96d0002:	add	byte ptr [rax], al
0x154e96d0004:	add	byte ptr [rax], al
0x154e96d0006:	add	byte ptr [rax], al
0x154e96d0008:	movabs	al, byte ptr [0xa000000154e96779]
0x154e96d0011:	jns	0x154e96d007a
0x154e96d0013:	jmp	0x154e96d016c
0x154e96d0018:	add	byte ptr [rax], al
0x154e96d001a:	jmp	0x154e96d0174
0x154e96d0020:	mov	al, 0xd
0x154e96d0022:	insd	dword ptr [rdi], dx
0x154e96d0023:	jmp	0x154e96d017c
0x154e96d0028:	add	byte ptr [rax], dl
0x154e96d002a:	insd	dword ptr [rdi], dx
0x154e96d002b:	jmp	0x154e96d0184
0x154e96d0030:	add	byte ptr [rax + 0x6d], dh
0x154e96d0033:	jmp	0x154e96d018c
0x154e96d0038:	add	dword ptr [rax], eax
0x154e96d003a:	add	byte ptr [rax], al
0x154e96d003c:	add	byte ptr [rax], al
0x154e96d003e:	add	byte ptr [rax], al
4852	powershell.exe	0x7df467630000	0x7df46763ffff	VadS	PAGE_EXECUTE_READWRITE	1	1	Disabled	
00 00 00 00 00 00 00 00	........
78 0d 00 00 00 00 00 00	x.......
45 00 00 00 49 c7 c2 00	E...I...
00 00 00 48 b8 60 47 e9	...H.`G.
a5 ff 7f 00 00 ff e0 49	.......I
c7 c2 01 00 00 00 48 b8	......H.
60 47 e9 a5 ff 7f 00 00	`G......
ff e0 49 c7 c2 02 00 00	..I.....	
0x7df467630000:	add	byte ptr [rax], al
0x7df467630002:	add	byte ptr [rax], al
0x7df467630004:	add	byte ptr [rax], al
0x7df467630006:	add	byte ptr [rax], al
0x7df467630008:	js	0x7df467630017
0x7df46763000a:	add	byte ptr [rax], al
0x7df46763000c:	add	byte ptr [rax], al
0x7df46763000e:	add	byte ptr [rax], al
0x7df467630010:	add	byte ptr [r8], r8b
0x7df467630013:	add	byte ptr [rcx - 0x39], cl
0x7df467630016:	ret	0
0x7df467630019:	add	byte ptr [rax], al
0x7df46763001b:	movabs	rax, 0x7fffa5e94760
0x7df467630025:	jmp	rax
0x7df467630027:	mov	r10, 1
0x7df46763002e:	movabs	rax, 0x7fffa5e94760
0x7df467630038:	jmp	rax
4852	powershell.exe	0x7df467640000	0x7df4676dffff	VadS	PAGE_EXECUTE_READWRITE	2	1	Disabled	
d8 ff ff ff ff ff ff ff	........
08 00 00 00 00 00 00 00	........
01 00 00 00 00 00 00 00	........
00 02 0e 03 38 00 00 00	....8...
68 41 d3 07 45 00 00 00	hA..E...
c0 6d 2f a3 ff 7f 00 00	.m/.....
00 10 bd a2 ff 7f 00 00	........
70 c5 c9 a2 ff 7f 00 00	p.......	
0x7df467640000:	fdivr	st(7)

```


`0xd50ebb98a080	\Users\Maison\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt	216`

TTS croissant 
GeoLocate function ?

I am jakoby wallpaper troll, maybe dump wallpaper to get the image:
```
This program enumerates a target PC to get their Name, GeoLocation (Latitude and Longitude), Public IP, Day password was last set, and wifi passwords. This information will be saved to a file that is then converted to a .BMP image. That image will be saved to their desktop and saved as their wallpaper. Opening the image on their desktop with NotePad will reveal the binary code with a hidden message at the bottom of the file.
```

```
$hiddenMessage = "Kissss"
```

```
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "LUL"
```

flag2 = LUL

```
$graphics.DrawString("e1ByQG5rM2Qt`n" + $content, $font, $brushFg, $centerX, 40) 
```

e1ByQG5rM2Qt --decode base64-->  {Pr@nk3d-

flag = `404CTF{Pr@nk3d-LUL}`