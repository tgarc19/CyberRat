from tkinter import *
from tkinter import ttk

root = Tk()
root.title("Cyber Rat")

#TODO tweek padding for our uses
mainframe = ttk.Frame(root, padding="3 3 12 12")
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

#TODO Widgets, these have a heiarchy make sure you follow the heiarchy

#TODO Event Handling, requires widgets events should call CyberRat or a Controller in the MVC design. 