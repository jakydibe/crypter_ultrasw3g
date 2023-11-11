import os
import subprocess
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox


def allega_file():
    file_path = filedialog.askopenfilename(title="Seleziona un file")
    if file_path:
        # Qui puoi gestire il percorso del file come desideri
        set_text(file_path, path_entry)
        print(f"File allegato: {file_path}")

def center_window(width=300, height=200):
    # get screen width and height
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    # calculate position x and y coordinates
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    window.geometry('%dx%d+%d+%d' % (width, height, x, y))



def set_text(text, entry):
    entry.delete(0,tk.END)
    entry.insert(0,text)
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
center_window(500, 400)


path_entry  = tk.Entry(window, width=50)
path_entry.place(relx=.1, rely=.11)

label1= tk.Label(window, text="Inserisci il tuo malware")
label1.place(relx=.1,rely=.05)
# Creazione del bottone per allegare il file
allega_button = tk.Button(window, text="Allega File", command=allega_file, relief="ridge", borderwidth=2)
allega_button.place(relx=.79, rely=.105)

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
        #output comando
        set_text("Malware Inserito correttamente nello stub",labelOUT)

#bottone avvia
exec_button = tk.Button(window, text="Avvia", command=esegui)
exec_button.place(relx=0.5, rely=0.25, anchor="center", width=100, height=30)




#cambio icona allo stub
labelOUT = tk.Label(window, text="")
labelOUT.place(relx=.1, rely=.6)
# Esecuzione del loop principale della finestra
window.mainloop()
