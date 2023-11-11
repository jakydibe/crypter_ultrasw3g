import os
import subprocess
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

def allega_file():
    file_path = filedialog.askopenfilename(title="Seleziona un file")
    if file_path:
        # Qui puoi gestire il percorso del file come desideri
        set_text(file_path)
        print(f"File allegato: {file_path}")

def set_text(text):
    path_entry.delete(0,tk.END)
    path_entry.insert(0,text)
    return

def mostra_finestra_di_dialogo(code):

    if code==1:
        messagebox.showinfo("Input Error", "Input non valido")
    elif code==2:
        messagebox.showinfo("Extension Error", "Il formato del file selezionato non è valido")
    elif code==3:
            messagebox.showinfo("Not a File Error", "Il path selezionato non corrisponde ad un file")
    elif code==4:
            messagebox.showinfo("Non existent Path Error", "Il path selezionato non esiste")



# Creazione della finestra principale
window = tk.Tk()
window.title("Crypter")
window.geometry("600x600")

path_entry  = tk.Entry(window, width=30)
path_entry.grid(row=1,column=1, padx= 30,pady=30)

# Creazione del bottone per allegare il file
allega_button = tk.Button(window, text="Allega File", command=allega_file)
allega_button.grid(row=1,column=2)

def checkExtension(f) :
    n= len(f)
    bool=False
    acceptedExtensions= [".exe"]
    for i in acceptedExtensions:
        print(f[n-len(i):])
        if f[n-len(i):]==i :
            bool = True
    return bool

def checkPath(percorso) :
    if os.path.exists(percorso):
        # Verifica se è un file
        if os.path.isfile(percorso):
            print(f"Il percorso '{percorso}' corrisponde a un file esistente.")
            return True
    return False

def verifica_percorso(percorso):
    # Verifica se il percorso esiste
    if os.path.exists(percorso):
        if os.path.isdir(percorso):
            print(f"Il percorso '{percorso}' corrisponde a una directory esistente.")
            return 3
        else:
            print(f"Il percorso '{percorso}' esiste, ma non è né un file né una directory.")
            return 3
    else:
        print(f"Il percorso '{percorso}' non esiste.")
        return 4


    

#caio
# Comando da eseguire
def esegui():
    file = path_entry.get()

    print(file)
    comando=None
    if(file == None or file == ""):
        #input non valido
        mostra_finestra_di_dialogo(1)
    elif(not checkPath(file)):
        #path non valido
        mostra_finestra_di_dialogo(verifica_percorso(file))
    elif(not checkExtension(file)):
        #estensione non valida
        mostra_finestra_di_dialogo(2)
    else:
        comando = "mio_crypter.exe " + file
        print(comando)
    # Esegui il comando
    if comando !=None:
        print(os.popen(comando).read())
        #os.system(comando)
        #risultato = subprocess.run(comando, shell=True, capture_output=True, text=True)
        # Stampa l'output del comando
        #print("Output del comando:", risultato.stdout)
        print("finito")
        # Stampa il codice di uscita
        #print("Codice di uscita:", risultato.returncode)

exec_button = tk.Button(window, text="Avvia", command=esegui)
exec_button.grid(row=5,column=5)



# Esecuzione del loop principale della finestra
window.mainloop()
