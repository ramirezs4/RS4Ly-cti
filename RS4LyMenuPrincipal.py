from RS4LyConsultas import AVTIP,AIPADBIP,AIQSIP,AIPADBSU,AIPADBSU
from RS4LyModuloPrincipal import RASU1,RAIP,RAIP2,RASU11,RASU12,RASU13,RASTO
import os
from colorama import init,Fore,Back,Style
init()


#Limpiar pantalla
def Limpiar():
    if os.name == "posix": os.system ("clear")
    elif os.name == "ce" or os.name == "nt" or os.name == "dos": os.system ("cls")



#Opcion1 del Menu principal
def Opcion1(EDO):
    IP1=input("Inserte la IP que quiere analizar ---> ")
    #Llamar a las funciones, y guardar la data en variables
    Data1=AIPADBIP(IP1)
    Data2=AIQSIP(IP1)
    Data3=AVTIP(IP1)
                
    #Pasar la data de la consulta a las funciones
    Limpiar()
    RAIP(IP1,Data1,Data2,Data3)
                
    print(Fore.LIGHTMAGENTA_EX+"\nOpciones Disponible:"+Fore.RESET," \n 1)Ver informacion completa \n 2)Guardar la data en un documento(No disponible) \n 0)Volver Atras")
    EDO=input()
                
    if EDO=="1":
        Limpiar()
        RAIP2(IP1,Data1,Data2,Data3)
        
    elif EDO=="0":
        Limpiar()

#Opcion2 del MenuPrincipal
def Opcion2():
    #Red="66.240.205.4/24"
    #no reportes
    
    #Red="61.177.173.1/24"
    #con reportes
    Red="192.168.0.1/24"
    
    #Red="74.125.0.2/24"
    #Red sin reportes
    
    #Red=input("Inserte la Red que quiere analizar(/24 o superior)")
    
    #Llamar a las funciones, y guardar la data en variables
    Data4=AIPADBSU(Red)
    #Llamada al modulo de anal2isis de datos
    RASU1(Red,Data4)

    print(Fore.LIGHTMAGENTA_EX+"\nOpciones Disponible:"+Fore.RESET," \n 1)Ver lista detallada por IP \n 2)Guardar la data en un documento(No disponible) \n 0)Volver Atras")
    EDO=input()
    
    while EDO=="1":
        try:
            if(Data4["reportedAddress"]>int(0)):
                Limpiar()
                print("La lista de IPs que pertenecen al rango mencionado se dividen en 3 grupos mencionados a continuacion:\n 1-Bajos Reportes, son las que contienen 10 o menos reportes.\n 2-Medio-Son las que contienen entre 10 y 50 reportes.\n 3-Altos reportes mas de 50 reportes.\n 4-Todas.\n 0-Salir")
                EDO=input("Lista ---->")
                if EDO=="1":
                    RASU11(Data4)
                    EDO="1"
                elif EDO=="2":
                    RASU12(Data4)
                    EDO="1"
                elif EDO=="3":
                    RASU13(Data4)
                    EDO="1"
                elif EDO=="4":
                    RASTO(Data4)
                    EDO="1"
                elif EDO=="0":
                    break       
        except KeyError:
            Limpiar()
            print("Las IPs de esta red no tienen reportes")
            break
    else:
        Limpiar()
    
#Menu de opciones
def MenuDeOpciones(EDO):
    while True:
        if EDO=="1":
            Limpiar()
            Opcion1(EDO)
            EDO=input("1-Continuar o 0-salir?")
            Limpiar()
        
        if EDO=="2":
            Limpiar()
            Opcion2()
            EDO=input("1-Continuar o 0-salir?")
            Limpiar()
            
        if EDO=="0":
            print("Cerrando Herramienta")
            Limpiar()
            break
            
        else:
            print("Eleccion no valida")
            Limpiar()
            break


#Menu usuario
while True:
    print ("Saludos, Seleccione una opcion\n","1-Analisis de ip\n","2-Analisis de red(/24 o mayor)(No disponible)\n","3-Analisis de url(No disponible)\n","4-Analisis de archivos(No disponible)\n","0-Salir\n")
    EDO=input("Su elección --> ")
    MenuDeOpciones(EDO)
    
    if EDO=="0":
        print("Cerrando la herramienta")
        break
