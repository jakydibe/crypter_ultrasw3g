# crypter_ultrasw3g
UTLIZZO (OVVIAMENTE DA WINDOWS, E DEVI SCARICARTI IL TERMINALE X64 DI VISUAL STUDIO):

1)cl.exe malware.cpp (semplicemente compila il tuo malware)

2)cl.exe mio_crypter.cpp

3)cl.exe mio_stub.cpp

4)mio_crypter.exe malware.exe  //crypter va a scrivere delle sezioni di mio_stub.exe mettendoci l' immagine criptata del malware nella sezione risorse

5)esegui mio_stub.exe


P.S La chiave l'ho generata casualmente, sono 32 byte completamente casuali



To DO:

- testare e semmai applicare crittografia piu' complessa

- Dare la possibilita' di fare piu' metodi di RunPE

- provare  a fare RunTime PE (Ad esempio potremmo criptare ogni istruzione che non e' piu' necessaria

- eliminare possibili metadati dallo stub(?)

- ---------------------------------------------- -

- Rendere GUI guardabile e intuitiva

- dalla GUI possibilità di inserire certificato allo stub (chiavi RSA)

- dalla GUI possibilità di cambiare l'icona dello stub
