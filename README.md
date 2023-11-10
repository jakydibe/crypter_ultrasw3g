# crypter_ultrasw3g
UTLIZZO (OVVIAMENTE DA WINDOWS, E DEVI SCARICARTI IL TERMINALE X64 DI VISUAL STUDIO):

1)cl.exe malware.cpp (semplicemente compila il tuo malware)\n
2)cl.exe mio_crypter.cpp\n
3)cl.exe mio_stub.cpp\n
4)mio_crypter.exe malware.exe  //crypter va a scrivere delle sezioni di mio_stub.exe mettendoci l' immagine criptata del malware nella sezione risorse\n
5) esegui mio_stub.exe\n

P.S La chiave l'ho generata casualmente, sono 32 byte completamente casuali
