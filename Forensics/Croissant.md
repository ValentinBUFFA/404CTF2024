```
sudo systemctl cryptenroll /dev/sda2 --recovery-key --wipe-slot=0
```
Recovery key: `dflnrftl-dghdcdcc-uljjvtdi-grrvdnne-lveeegci-bclknhtf-jgrikeui-glfbdfru` <== may be entered in place of a password
This key is stored in slot 2, and slot 0 (password) has been wiped

16 `.s*` files, each around 512MB

The mention of ADI3 makes it seem like the dump has been made using FTK imager

```sh
> file AlexisLaptop.s01  
AlexisLaptop.s01: EWF/Expert Witness/EnCase image file format
> ewfmount AlexisLaptop.s01 output
> file output/ewf
output/ewf1: DOS/MBR boot sector; partition 1 : ID=0xee, start-CHS (0x0,0,2), end-CHS (0x3ff,255,63), startsector 1, 16777215 sectors, extended partition table (last)
> fdisk -l output/ewf1  
Périphérique   Début      Fin Secteurs Taille Type  
output/ewf1p1   2048   616447   614400   300M Système EFI  
output/ewf1p2 616448 16775167 16158720   7,7G Racine Linux (x86-64)
```
It looks like we have the image of a full disk dump

Let's ignore the efi partition **for now** and mount ewf1p2



User uses arch linux
![croissant1.png](/images/croissant1.png)

In timeshift snapshots we can see a file in /root
the pam_unix.so could be the malicious file

diff gives:
```
Les fichiers binaires 1QoOr (1)/usr/lib/security/pam_unix.so et pam-1.6.0-3-x86_64.pkg/usr/lib/security/pam_unix.so sont différents
```

We use vbindiff to find where the binaries started being different, around 0x00005900
![[croissant2.png]]

With Ghidra, we look at address 0x01005900
this is in the malicious *.so* but not in the base one- it appears to be the `_unix_verify_password(pamh, name, p, ctrl);` function
```c
  local_308 = 0;
  bVar23 = 0;
  
  local_328 = 0x6f5f4577;
  uStack_324 = 0x9688907c;
  uStack_320 = 0x4705b114;
  uStack_31c = 0x1b4e8e33;
  local_318 = 0x1032828b8af8070a;
  uStack_310 = 0x5fbb2a55;
  uStack_30c = 0x1c3fc671;
  
  local_2c8 = 0xf2f3d6282c6b7543;
  uStack_2c0 = 0x770fd15d7631dc27;
  local_2b8 = 0x7654b2d4bf917f39;
  uStack_2b0 = 0x2ce44f27;
  uStack_2ac = 0x6c60881e;
  local_2a8 = 0x11f3644;
  uStack_2a4 = 0xf3cccf08;
  uStack_2a0 = 0x7777d24b;
  uStack_29c = 0x7a3dfd5a;
  uStack_298 = 0x6dd7ead58b3044;
  uStack_291 = 0xbb342dc95f6672;
  
  lVar10 = 0;
  do {
    if (param_3[lVar10] == 0) break;
    lVar15 = lVar10 + 1;
    bVar23 = bVar23 | param_3[lVar10] ^ *(byte *)((long)&local_2c8 + lVar10) ^
                         *(byte *)((long)&local_328 + (ulong)((uint)lVar10 & 0x1f));
    lVar10 = lVar15;
  } while (lVar15 != 0x3e);
  if ((bVar23 == 0) || (bVar22)) {
    if (local_388 != (char *)0x0) {
      pam_set_data(param_1,local_388,0,FUN_00102e50);
    }
    iVar3 = 0;
  }
```

Ghidra decompiled it weirdly so we must reconstruct the stack manually:
```python
long1 = 0xbb342dc95f66726dd7ead58b30447a3dfd5a7777d24bf3cccf08011f36446c60881e2ce44f277654b2d4bf917f39770fd15d7631dc27f2f3d6282c6b7543
tab1 = long1.to_bytes(62, 'little') # 62 = 0x3e

long2 = 0x1c3fc6715fbb2a551032828b8af8070a1b4e8e334705b1149688907c6f5f4577
tab2 = long2.to_bytes(32, 'little')

xored = []
for i in range(len(tab1)):
    xored.append(tab1[i]^tab2[i&0x1f])
xored=bytes(xored)
print(xored)
```

We get the flag !