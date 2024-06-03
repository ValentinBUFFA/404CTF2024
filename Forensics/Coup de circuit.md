# 1
C'est la catastrophe ! Je me prépare pour mon prochain match de baseball, mais on m'a volé mon mojo ! Sans lui, je vais perdre, c'est certain... Je crois qu'on m'a eu en me faisant télécharger un virus ou je ne sais quoi, et le fichier a été supprimé de mon ordinateur. J'ai demandé de l'aide à un ami expert et il a extrait des choses du PC, mais il n'a pas le temps d'aller plus loin. Vous pourriez m'aider ?

---

Identifiez le malware et donnez son condensat sha1. Le flag est au format suivant : `404CTF{sha1}`

----

## Infos
```
Collection  
├── amcache  
│   ├── 20240505010820_Amcache_DeviceContainers.csv  
│   ├── 20240505010820_Amcache_DevicePnps.csv  
│   ├── 20240505010820_Amcache_DriveBinaries.csv  
│   ├── 20240505010820_Amcache_DriverPackages.csv  
│   ├── 20240505010820_Amcache_ShortCuts.csv  
│   └── 20240505010820_Amcache_UnassociatedFileEntries.csv  
├── mft  
│   └── 20240505000512_MFTECmd_$MFT_Output.csv  
└── prefetch  
   ├── 20240504235816_PECmd_Output.csv  
   └── 20240504235816_PECmd_Output_Timeline.csv
```

[Amcache analysis](https://cyber.gouv.fr/publications/amcache-analysis): The AmCache is an artifact which stores metadata related to PE execution and program installation on Windows 7 and Server 2008 R2 and above.

[Master File Table](https://www.asdfed.com/Master-File-Table-and-Computer-Forensics): It is a database that contains essential information about every file and directory on a computer's hard drive. The MFT keeps track of a file's location on the hard drive and manages other attributes.

[Prefetch](https://www.sciencedirect.com/topics/computer-science/prefetch): Prefetch files are used by Windows to store information in relation to software activity, 

## Analyse

### MFT
Un seul gros fichier __20240505000512_MFTECmd_\$MFT_Output.csv__

| EntryNumber     | SequenceNumber | InUse | ParentEntryNumber | ParentSequenceNumber | ParentPath | FileName | Extension | FileSize | ReferenceCount | ReparseTarget | IsDirectory | HasAds | IsAds | SI<FN | uSecZeros | Copied | SiFlags | NameType | Created0x10 | Created0x30 | LastModified0x10 | LastModified0x30 | LastRecordChange0x10 | LastRecordChange0x30 | LastAccess0x10 | LastAccess0x30 | UpdateSequenceNumber | LogfileSequenceNumber | SecurityId | ObjectIdFileDroid | LoggedUtilStream | ZoneIdContents |
| --------------- | -------------- | ----- | ----------------- | -------------------- | ---------- | -------- | --------- | -------- | -------------- | ------------- | ----------- | ------ | ----- | ----- | --------- | ------ | ------- | -------- | ----------- | ----------- | ---------------- | ---------------- | -------------------- | -------------------- | -------------- | -------------- | -------------------- | --------------------- | ---------- | ----------------- | ---------------- | -------------- |
| *\~200k lignes* |                |       |                   |                      |            |          |           |          |                |               |             |        |       |       |           |        |         |          |             |             |                  |                  |                      |                      |                |                |                      |                       |            |                   |                  |                |

### prefetch


**0240504235816_PECmd_Output.csv**

| Note | SourceFilename | SourceCreated | SourceModified | SourceAccessed | ExecutableName | Hash | Size | Version | RunCount | LastRun | PreviousRun0 | PreviousRun1 | PreviousRun2 | PreviousRun3 | PreviousRun4 | PreviousRun5 | PreviousRun6 | Volume0Name | Volume0Serial | Volume0Created | Volume1Name | Volume1Serial | Volume1Created | Directories |
| ---- | -------------- | ------------- | -------------- | -------------- | -------------- | ---- | ---- | ------- | -------- | ------- | ------------ | ------------ | ------------ | ------------ | ------------ | ------------ | ------------ | ----------- | ------------- | -------------- | ----------- | ------------- | -------------- | ----------- |
| *280 lignes*     |                |               |                |                |                |      |      |         |          |         |              |              |              |              |              |              |              |             |               |                |             |               |                |             |

-----

**20240504235816_PECmd_Output_Timeline.csv**

| RunTime      | ExecutableName |
| ------------ | -------------- |
| *927 lignes* |                |

### Amcache
Tout les csv sont vides sauf __20240505010820_Amcache_UnassociatedFileEntries.csv__

| ApplicationName | ProgramId | FileKeyLastWriteTimestamp | SHA1 | IsOsComponent | FullPath | Name | FileExtension | LinkDate | ProductName | Size | Version | ProductVersion | LongPathHash | BinaryType | IsPeFile | BinFileVersion | BinProductVersion | Usn | Language | Description |
| --------------- | --------- | ------------------------- | ---- | ------------- | -------- | ---- | ------------- | -------- | ----------- | ---- | ------- | -------------- | ------------ | ---------- | -------- | -------------- | ----------------- | --- | -------- | ----------- |
| *83 lignes*     |           |                           |      |               |          |      |               |          |             |      |         |                |              |            |          |                |                   |     |          |             |


Processus avec un nom suspect, exécuté depuis les téléchargements:

| ApplicationName | ProgramId                                    | FileKeyLastWriteTimestamp | SHA1                                     | IsOsComponent | FullPath                                | Name            | FileExtension | LinkDate            | ProductName | Size    | Version | ProductVersion | LongPathHash | BinaryType | IsPeFile | BinFileVersion | BinProductVersion | Usn       | Language | Description |
| --------------- | -------------------------------------------- | ------------------------- | ---------------------------------------- | ------------- | --------------------------------------- | --------------- | ------------- | ------------------- | ----------- | ------- | ------- | -------------- | ------------ | ---------- | -------- | -------------- | ----------------- | --------- | -------- | ----------- |
| Unassociated    | 0006799086f2b3631ed09571eea308213bed0000ffff | 2024-05-04 23:06:35       | 5cf530e19c9df091f89cede690e5295c285ece3c | False         | c:\users\rick\downloads\sflgdqsfhbl.exe | sflgdqsfhbl.exe | .exe          | 2024-05-04 17:11:14 |             | 7319454 |         |                |              | pe64_amd64 | False    |                |                   | 219273384 | 0        |             |

# 2
Super ! Grace à vous j'ai pu retirer le fichier de mon PC, mais pensez-vous qu'il serait possible d'en savoir un peu plus sur ce malware ?

---

Retrouvez l'interface web du panneau de Command & Control du malware.

Le flag y sera reconnaissable.

----

Trouvons plus d'info dans le dump MFT et prefetch sur sflgdqsfhbl.exe
On cherche le hash du malware sur [Virus Total](https://www.virustotal.com/gui/file/439bfbdc4ef8d94d36273714d7ef4a709e7228f7daf85aaa1cd295354ee5cb98/details)
L'onglet "Relations" nous donne l'adresse: *takemeouttotheballgame.space*
En cherchant ce nom de domaine sur Virus Total à son tour on trouve deux adresses:
- *panel-5d4213f3bf078fb1656a3db8348282f482601690.takemeouttotheballgame.space* - 162.19.109.162
- *ftp.takemeouttotheballgame.space* - 162.19.101.129

La première adresse est accessible en http et nous redirige vers une page de connexion, content notamment le flag pour cette étape.
