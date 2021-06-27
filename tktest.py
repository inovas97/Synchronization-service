import time
from tkinter import *
    


    
top = Tk()  
label =  Label(top, text = "ok")
    
def sett():
    label.text = "hello mam"
    label.place(x= 30, y=190)
    
def delete():
    label.destroy()

top.geometry("400x250")  
  
#creating label  
uname = Label(top, text = "Username").place(x = 30,y = 50)  
  
#creating label  
password = Label(top, text = "Password").place(x = 30, y = 90)  
  
  
sbmitbtn = Button(top, text = "Submit",activebackground = "pink", activeforeground = "blue",command=sett).place(x = 30, y = 120)  
sbmitbtn = Button(top, text = "DELETE",activebackground = "pink", activeforeground = "blue",command=delete).place(x = 30, y = 160)  
  
e1 = Entry(top,width = 20).place(x = 100, y = 50)  
  
  
e2 = Entry(top, width = 20).place(x = 100, y = 90)  
  

  
top.mainloop()  