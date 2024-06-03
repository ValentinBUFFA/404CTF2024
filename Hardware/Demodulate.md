# 1 - ASK
Porteuse : 7kHz
Fréquence d'échantillonage : 350kHz
Valence : 256
Débit : 1000 symboles/sec
Format : float32

Un symbole = 1 octet (valence 256) ?
350k/1000 = 350 samples pour un symbole ?

----

Voir `demod-1.ipynb` pour le calcul de démodulation en pure Python. Aurait pu être faisable aussi avec l'aide de GNU Radio.
Les 4 premiers octets trouvés `b'\x89PNG` permettent de déterminer le format de sortie à la démodulation.
![demod1.png](/images/demod1.png)
# 2 - OFDM
NB_SOUS_PORTEUSES = 8
Porteuse : F_C = 7kHz
Fréquence d'échantillonage : F_E = 350kHz
Valence : 256

T_E = 1/F_E
R = 1000
T = 1/R

---- 

On doit reconstruire une image png

Le détail de résolution de ce challenge se trouve dans le notebook `demod-2.ipynb`, cette fois aussi en pure Python.
Le format du flag est encore un fichier png:
![demod2.png](/images/demod2.png)
