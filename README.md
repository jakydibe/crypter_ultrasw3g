# crypter_ultrasw3g
UTLIZZO (OVVIAMENTE DA WINDOWS, E DEVI SCARICARTI IL TERMINALE X64 DI VISUAL STUDIO):

1)cl.exe malware.cpp (semplicemente compila il tuo malware)
2)cl.exe mio_crypter.cpp
3)cl.exe mio_stub.cpp
4)mio_crypter.exe malware.exe  //crypter va a scrivere delle sezioni di mio_stub.exe mettendoci l' immagine criptata del malware nella sezione risorse
5) esegui mio_stub.exe
