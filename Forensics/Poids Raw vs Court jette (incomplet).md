>Vrai malware, faire attention à ce que j'exécute et faire l'analyse dynamique sur une sandbox


Bienvenue chez **Entreprendre** !

Nous sommes une entreprise jeune et dynamique spécialisée dans les poids. Si vous appréciez observer des boulets se projeter, enfin se faire projeter, venez lancer les nôtres !

Nous avons remarqué une perte de réseau récemment et il semblerait que le switch **feuille3** ait redémarré pour des raisons inexplicables. Notre responsable du réseau a investigué mais rien trouvé d'étrange. Dans le doute, il a fait une **capture de RAM** du switch et vous désigne vous, **oui vous**, pour trouver ce qui cloche.
# 1/3
Nous pensons qu'il s'agit là d'un coup de nos rivaux : **Imagine**... Ces derniers travaillent dans le lancer de javelot, une discipline hérétique et vulgaire qui nous écœure ! Nous aurions dû faire attention et mettre des mots de passe plus forts sur nos équipements !
Trouvez le **pid** et le hash **md5** du malware présent sur le switch

Format du Flag : `404CTF{111:891f490e5d7bdb06d90d56f8d7db405f}`

----
Fichier: memory.elf (md5sum: 0cbf0505e5c6e216fadf8728b28afae4)
```
readelf -h memory.elf  
En-tête ELF:  
 Magique:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00    
 Classe:                            ELF64  
 Données:                          complément à 2, système à octets de poids faible d'abord (little endian)  
 Version:                           1 (actuelle)  
 OS/ABI:                            UNIX - System V  
 Version ABI:                       0  
 Type:                              CORE (fichier core)   <==
 Machine:                           Advanced Micro Devices X86-64  
 Version:                           0x1  
 Adresse du point d'entrée:         0x0  
 Début des en-têtes de programme :  192 (octets dans le fichier)  
 Début des en-têtes de section :    64 (octets dans le fichier)  
 Fanions:                           0x0  
 Taille de cet en-tête:             8 (octets)  
 Taille de l'en-tête du programme:  56 (octets)  
 Nombre d'en-tête du programme:     5  
 Taille des en-têtes de section:    64 (octets)  
 Nombre d'en-têtes de section:      2  
 Table d'index des chaînes d'en-tête de section: 1
```

>[!cite]
>ELF core [1](https://lief.re/doc/latest/tutorials/12_elf_coredump.html#id2) files provide information about the CPU state and the memory state of a program when the coredump has been generated. The memory state embeds a _snapshot_ of all segments mapped in the memory space of the program. The CPU state contains register values when the core dump has been generated.

Références:
- https://www.gabriel.urdhr.fr/2015/05/29/core-file/
- https://lief.re/doc/latest/tutorials/12_elf_coredump.html

ELF segment: état de la mémoire
ELF PT Note: état des registres CPU

On peut utiliser LIEF pour parse tout ça:
- https://github.com/lief-project/LIEF
- https://lief.re/doc/latest/index.html
Ainsi que readelf pour commencer, en lisant par exemple les notes (registres CPU)
```
readelf -n memory.elf  
  
Affichage des notes trouvées au décalage de fichier 0x000001d8 avec une longueur de 0x00000660 :  
 Propriétaire        Taille des données        Description  
 CORE                 0x00000150       NT_PRSTATUS (structure prstatus)  
 CORE                 0x00000150       NT_PRSTATUS (structure prstatus)  
 QEMU                 0x000001b8       Type de note inconnu: (0x00000000)  
  données de description: 01 00 00 00 b8 01 00 00 a0 11 3f aa ff ff ff ff 00 00 00 00 00 00 00 00 80 0a c3 ff 73 9a ff ff 06 0e 04 00 00 00 00 00 00 00 00 00 00 00 00 00 71 14 3f aa ff ff  
ff ff 88 3e e0 aa ff ff ff ff e0 78 09 ab ff ff ff ff fe 7f 87 6c a0 00 00 00 01 00 00 00 00 00 00 00 40 a2 e5 aa ff ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
00 00 00 ff ff ff ff ff ff ff ff 40 39 e1 aa ff ff ff ff 0e 13 3f aa ff ff ff ff 86 02 00 00 00 00 00 00 10 00 00 00 ff ff ff ff 00 9b a0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0 ff 73 9a ff ff 18 00 00 00 ff ff ff ff 00 93 c0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 87 40 00 00 00 8b 00 00 00 00 00 00 00 30 00 00 00 fe ff ff 00 00 00 00 7f 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 fe ff ff 00  
00 00 00 ff 0f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 fe ff ff 33 00 05 80 00 00 00 00 00 00 00 00 00 00 00 00 20 47 74 e9 49 7f 00 00 00 60 58 0c 00 00 00 00 f0 0e 75 00 00 00 00 00  
00 00 00 00 00 00 00 00    
 QEMU                 0x000001b8       Type de note inconnu: (0x00000000)  
  données de description: 01 00 00 00 b8 01 00 00 a0 11 3f aa ff ff ff ff 01 00 00 00 00 00 00 00 80 0a d3 ff 73 9a ff ff 86 3e 04 00 00 00 00 00 00 00 00 00 00 00 00 00 71 14 3f aa ff ff  
ff ff c8 3e 08 40 19 ac ff ff e0 78 09 ab ff ff ff ff 9d 98 87 6c a0 00 00 00 00 00 00 00 00 00 00 00 0f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
00 00 00 ff ff ff ff ff ff ff ff 00 00 24 81 73 9a ff ff 0e 13 3f aa ff ff ff ff 82 02 00 00 00 00 00 00 10 00 00 00 ff ff ff ff 00 9b a0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 d0 ff 73 9a ff ff 18 00 00 00 ff ff ff ff 00 93 c0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 87 40 00 00 00 8b 00 00 00 00 00 00 00 e0 03 00 00 fe ff ff 00 00 00 00 7f 00 00 00 00 00 00 00 00 00 00 00 00 c0 03 00 00 fe ff ff 00  
00 00 00 ff 0f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 fe ff ff 33 00 05 80 00 00 00 00 00 00 00 00 00 00 00 00 c8 04 5d 05 00 00 00 00 00 60 58 0c 00 00 00 00 e0 0e 75 00 00 00 00 00  
00 00 00 00 00 00 00 00
```

We have two cpu cores (2 CORE notes), we must parse the QEMU notes manually.

It seems that execution stopped at 0xffffffffaa3f130e, where trying to access unauthorized/unavailable(?) memory section:
```
(gdb) where  
#0  0xffffffffaa3f130e in ?? ()  
Backtrace stopped: Cannot access memory at address 0xffffffffaae03e88
```

We can get information on segments using readelf:
```
En-têtes de programme :  
 Type           Décalage           Adr.virt           Adr.phys.  
                Taille fichier     Taille mémoire      Fanion Alignement  
 NOTE           0x00000000000001d8 0x0000000000000000 0x0000000000000000  
                0x0000000000000660 0x0000000000000660         0x0  
 LOAD           0x0000000000000838 0x0000000000000000 0x0000000000000000  
                0x00000000000a0000 0x00000000000a0000         0x0  
 LOAD           0x00000000000a0838 0x00000000000c0000 0x00000000000c0000  
                0x000000007ff40000 0x000000007ff40000         0x0  
 LOAD           0x000000007ffe0838 0x00000000fa800000 0x00000000fa800000  
                0x0000000000800000 0x0000000000800000         0x0  
 LOAD           0x00000000807e0838 0x00000000fffc0000 0x00000000fffc0000  
                0x0000000000040000 0x0000000000040000         0x0
```

Let's extract different memory regions from the elf core dump:
```
dd if=memory.elf of=load1.dmp bs=1 count=$((0x00000000000a0000)) skip=$((0x0000000000000838))
```
The first LOAD one (load1.dmp) looks a lot like a ram partition reserved for the bootloader:
- lots of mention of grub

volatility banners
```
0x6fbf6d8       Linux version 5.10.0-cl-1-amd64 (dev-support@cumulusnetworks.com) (gcc-8 (Debian 8.3.0-6) 8.3.0, GNU ld (GNU Binutils for Debian) 2.31.1) #1 SMP Debian 5.10.189-1+cl5.8.0u16  
(2024-01-27)  
0xebd71a0       Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0xebd7430       Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0xebd7718       Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0xebd7860       Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0xebd7a40       Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0xebd7cd0       Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x122df290      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x122df440      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x122df588      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x122df6d0      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x122df8b0      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x122dfe20      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x139efe48      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x1538bc98      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x153945a0      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x15394830      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x15394b20      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x15394e20      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x15395c20      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x15395ea0      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x1f044f80      Linux version 5.10.0-cl-1-amd64 (dev-support@cumulusnetworks.com) (gcc-8 (Debian 8.3.0-6) 8.3.0, GNU ld (GNU Binutils for Debian) 2.31.1) #1 SMP Debian 5.10.189-1+cl5.8.0u16  
(2024-01-27)  
0x41559388      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x41559b88      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x4155bb88      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x4155eb88      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x4bb06130      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x4bb52768      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x4fac94e0      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x4fac9770      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x4faca0f8      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x4faca580      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x4faca760      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x4faca9f0      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x4facae78      Linux version 5.8.0 running on QEMU Standard PC (Q35 + ICH9, 2009)  
0x51a001e0      Linux version 5.10.0-cl-1-amd64 (dev-support@cumulusnetworks.com) (gcc-8 (Debian 8.3.0-6) 8.3.0, GNU ld (GNU Binutils for Debian) 2.31.1) #1 SMP Debian 5.10.189-1+cl5.8.0u16  
(2024-01-27)  
0x535bec18      Linux version 5.10.0-cl-1-amd64 (dev-support@cumulusnetworks.com) (gcc-8 (Debian 8.3.0-6) 8.3.0, GNU ld (GNU Binutils for Debian) 2.31.1) #1 SMP Debian 5.10.189-1+cl5.8.0u16  
(2024-01-27)
```

Here is a documentation with mention of QEMU core dump: https://blogs.oracle.com/linux/post/whats-inside-a-linux-kernel-core-dump
and the implementation of QEMU core dump: https://github.com/qemu/qemu/blob/master/dump/dump.c


# Parsing note
## CORE
```
Note #0
-------
CORE_PRSTATUS(0x0001) 'CORE' [00 00 00 00 00 00 00 00 00 00 ...]
  PID: 0001 PPID: 0000 PGRP: 0000
  SID: 0000 SIGNO: 0000 SIGCODE: 0000
  SIGERR: 0000 SIGPEND: 0000 SIGHOLD: 0000
  CURRSIG: 0x0000 reserved: 0
   R15: 0xffffffffaae13940
   R14: 0xffffffffffffffff
   R13: 0x00000000
   R12: 0x00000000
   RBP: 0xffffffffab0978e0
   RBX: 0x00000000
   R11: 0x00000000
   R10: 0xffffffffaae5a240
   R9: 0x00000001
   R8: 0xa06c877ffe
   RAX: 0xffffffffaa3f11a0
   RCX: 0xffff9a73ffc30a80
   RDX: 0x00040e06
   RSI: 0x00000000
   RDI: 0xffffffffaa3f1471
   ORIG_RAX: 0x00000000
   RIP: 0xffffffffaa3f130e
   CS: 0x00000010
   EFLAGS: 0x00000286
   RSP: 0xffffffffaae03e88
   SS: 0x00000018

Note #1
-------
CORE_PRSTATUS(0x0001) 'CORE' [00 00 00 00 00 00 00 00 00 00 ...]
  PID: 0002 PPID: 0000 PGRP: 0000
  SID: 0000 SIGNO: 0000 SIGCODE: 0000
  SIGERR: 0000 SIGPEND: 0000 SIGHOLD: 0000
  CURRSIG: 0x0000 reserved: 0
   R15: 0xffff9a7381240000
   R14: 0xffffffffffffffff
   R13: 0x00000000
   R12: 0x00000000
   RBP: 0xffffffffab0978e0
   RBX: 0x00000001
   R11: 0x00000000
   R10: 0x0000000f
   R9: 0x00000000
   R8: 0xa06c87989d
   RAX: 0xffffffffaa3f11a0
   RCX: 0xffff9a73ffd30a80
   RDX: 0x00043e86
   RSI: 0x00000000
   RDI: 0xffffffffaa3f1471
   ORIG_RAX: 0x00000000
   RIP: 0xffffffffaa3f130e
   CS: 0x00000010
   EFLAGS: 0x00000282
   RSP: 0xffffac1940083ec8
   SS: 0x00000018
```