import os
from colorama import Back, Fore, Style, init
from RS4LyAnalisisDeDatos import (AdspaceRASU, CDNombre, NumReportIpAbuseDb,
                                  NumUserIpAbuseDb, PaisIPAbuseDB,
                                  PuntuacionAIPADBIP, PuntuacionAIPVT,
                                  PuntuacionAPIPQ,NumToHS,PasHost,NivRieSu,ResolutVT)
from RS4LyConsultas import AIQSIP

init()

#Limpiar pantalla
def Limpiar():
    if os.name == "posix": os.system ("clear")
    elif os.name == "ce" or os.name == "nt" or os.name == "dos": os.system ("cls")

#Datos del análisis resumido de la IP
def RAIP(IP1,Data1,Data2,Data3):
    #Evaluar si es una dirrecion publica  o no
    if (Data1["data"]["isPublic"]==False):
        IPR="Privada"
    else:
        IPR="Publica"

    while True:
        if IPR=="Publica":
            #Condiciones intermedias
            if(Data1["data"]["abuseConfidenceScore"]>30):
                M1=Fore.RED+"Maliciosa"+Fore.RESET
            else:
                M1=Fore.GREEN+"Limpia"+Fore.RESET
            if(Data2["fraud_score"]>30):
                M2=Fore.RED+"Maliciosa"+Fore.RESET
            else:
                M2=Fore.GREEN+"Limpia"+Fore.RESET

            if(ResolutVT(Data3)>1):
                M3=Fore.RED+"Maliciosa"+Fore.RESET
            else:
                M3=Fore.GREEN+"Limpia"+Fore.RESET

        
            Puntuacion=PuntuacionAPIPQ(Data2)
            #Despues que sabemos que es publica analizamos los datos
            print(Fore.BLUE+"El análisis de la direccion",IP1,"arrojo los siguientes resultados:\n"+Fore.RESET,"a)La dirección pertenece a una red: Publica\n b)El nivel de riesgo es:",Puntuacion,)
            print("\nFuentes:\n 1) IP Abuse DB:",M1,"\n 2) IP Quality Score:",M2,"\n 3) Virus Total:",M3)
            Fore.RESET
            break
        
        elif IPR=="Privada":
            print("La IP pertenece a una Red Privada")
            break
        
#Datos del análisis Completo de la IP
def RAIP2(IP1,Data1,Data2,Data3):
    #LLamadas a funciones
    PuntuacionAIPADBIP1=PuntuacionAIPADBIP(Data1)
    PuntuacionAPIPQ1=PuntuacionAPIPQ(Data2)
    PuntuacionAIPVT1=PuntuacionAIPVT(Data3)
    CantidadU=NumUserIpAbuseDb(Data1)
    CantidadR=NumReportIpAbuseDb(Data1)
    PaisIp=PaisIPAbuseDB(Data2)

    CDV=ResolutVT(Data3)
    CND=CDNombre(CDV)

     #Evaluar diferentes condiciones

    if (Data1["data"]["isPublic"]=="False"): IPR="Privada"
    else: IPR="Publica"
        
    if(Data1["data"]["abuseConfidenceScore"]>30): M1=Fore.RED+"Maliciosa"+Fore.RESET
    else: M1=Fore.GREEN+"Limpia"+Fore.RESET
    
    if(Data2["fraud_score"]>30): M2=Fore.RED+"Maliciosa"+Fore.RESET
    else: M2=Fore.GREEN+"Limpia"+Fore.RESET
    
    if(Data2["bot_status"]==True): bot=Fore.RED+"si"+Fore.RESET
    else: bot=Fore.GREEN+"No"+Fore.RESET
    
    if(Data2["proxy"]==True): proxy=Fore.RED+"si"+Fore.RESET
    else: proxy=Fore.GREEN+"No"+Fore.RESET
    
    if(Data2["active_vpn"]==True): vpn=Fore.RED+"si"+Fore.RESET
    else: vpn=Fore.GREEN+"No"+Fore.RESET

    if(Data2["active_tor"]==True): tor=Fore.RED+"si"+Fore.RESET
    else: tor=Fore.GREEN+"No"+Fore.RESET
    
    #Data3 Detectar urls con la direccion

    if(ResolutVT(Data3)>1): M3=Fore.RED+"Maliciosa"+Fore.RESET
    else: M3=Fore.GREEN+"Limpia"+Fore.RESET

    try:   
        #Evaluar los cambios de nombre    
        if(CND=="Si, 1-Pocos"):
            try:
                CND1="1er Nombre:",Data3["resolutions"][0]["hostname"],"Fecha del resultado",Data3["resolutions"][0]["last_resolved"]
                CND2="2do Nombre:",Data3["resolutions"][1]["hostname"],"Fecha del resultado",Data3["resolutions"][1]["last_resolved"]
            except KeyError:
                CND1="1er Nombre no recuperado"
                CND2="2do Nombre no recuperado"
        else:
            try:
                CND1="1er Nombre:",Data3["resolutions"][0]["hostname"],"Fecha del resultado:",Data3["resolutions"][0]["last_resolved"]
                CND2="2do Nombre:",Data3["resolutions"][1]["hostname"],"Fecha del resultado:",Data3["resolutions"][1]["last_resolved"]
                #CND3="3er Nombre:",Data3["resolutions"][2]["hostname"],"Fecha del resultado:",Data3["resolutions"][2]["last_resolved"]
            except KeyError:
                CND1="1er Nombre no recuperado"
                CND2="2do Nombre no recuperado"
            
    except IndexError:
        CND1="1er Nombre anterior no encontrado"
        CND2="2do Nombre anterior no encontrado"
    
        
    #Muestras descargadas detectadas
    try:
        DDS=len(Data3["detected_downloaded_samples"])
        if(int(DDS)>1): DDS2="Si","un total de",DDS
        else: DDS2="No detectado"
    except KeyError:
        DDS2="No detectado"

    #Final Evaluar diferentes condicione
    while True:
        if IPR=="Publica":
            try:
                Puntuacion=PuntuacionAIPADBIP(Data1)
                #Despues que sabemos que es publica analizamos los datos
                print(Fore.BLUE+"El análisis de la direccion"+Fore.RESET,IP1,"arrojo los siguientes resultados:","\n","a) La dirección pertenece a una red:",Fore.CYAN+"Publica"+Fore.RESET,"\n b) El nivel de riesgo es:",PuntuacionAPIPQ1,"\n c) Usuarios que han reportado esta Ip:",Data1["data"]['numDistinctUsers'],CantidadU,"\n d) El numero de reportes que pose(aproximado):",Data1["data"]['totalReports'],CantidadR,"\n e) Ultima vez que se reporto",Fore.CYAN+str(Data1["data"]["lastReportedAt"])+Fore.RESET,"\n f) El ISP actual es:",Fore.CYAN+str(Data2['ISP'])+Fore.RESET,"\n g) El nombre del dominio es:",Fore.CYAN+str(Data1["data"]["domain"])+Fore.RESET,"\n h) El nombre del host es:",Fore.CYAN+str(Data2["host"])+Fore.RESET,"\n i) Informacion Geografica:",PaisIp,"\n j) Presenta trafico no humano (bot):",bot,"\n k) Puede ser una conexion tipo: Proxy",proxy,", VPN",vpn,", Nodo Tor",tor,"\n l) Tipo de uso:",Fore.CYAN+str(Data1["data"]["usageType"])+Fore.RESET)
                print(Fore.LIGHTMAGENTA_EX+"\nFuentes:"+Fore.RESET,"\n 1) IP Abuse DB:",M1,"Puntuacion Individual de riesgo:",PuntuacionAIPADBIP1,"\n 2) IP Quality Score:",M2,"Puntuacion Individual:",PuntuacionAPIPQ1,"\n 3) Virus Total:",M3,"Puntuacion Individual:",PuntuacionAIPVT1)
                print(Fore.LIGHTMAGENTA_EX+"\nCambios de Nombre:\n"+Fore.RESET,"El host ha cambiado de nombre:",CND,", un total de:",ResolutVT(Data3),"\n",CND1,"\n",CND2)
                print(Fore.LIGHTMAGENTA_EX+"\nURLs y Muestras Descargadas:"+Fore.RESET,"\n Urls en esta IP Detectadas como maliciosas:",len(Data3["detected_urls"]),"\n Muestras descargadas detectadas:",DDS2)
            except KeyError:
                Puntuacion=PuntuacionAIPADBIP(Data1)
                #Despues que sabemos que es publica analizamos los datos
                print(Fore.BLUE+"El análisis de la direccion"+Fore.RESET,IP1,"arrojo los siguientes resultados:","\n","a) La dirección pertenece a una red:",Fore.CYAN+"Publica"+Fore.RESET,"\n b) El nivel de riesgo es:",PuntuacionAPIPQ1,"\n c) Usuarios que han reportado esta Ip:",Data1["data"]['numDistinctUsers'],CantidadU,"\n d) El numero de reportes que pose(aproximado):",Data1["data"]['totalReports'],CantidadR,"\n e) Ultima vez que se reporto",Fore.CYAN+str(Data1["data"]["lastReportedAt"])+Fore.RESET,"\n f) El ISP actual es:",Fore.CYAN+str(Data2['ISP'])+Fore.RESET,"\n g) El nombre del dominio es:",Fore.CYAN+str(Data1["data"]["domain"])+Fore.RESET,"\n h) El nombre del host es:",Fore.CYAN+str(Data2["host"])+Fore.RESET,"\n i) Informacion Geografica:",PaisIp,"\n j) Presenta trafico no humano (bot):",bot,"\n k) Puede ser una conexion tipo: Proxy",proxy,", VPN",vpn,", Nodo Tor",tor,"\n l) Tipo de uso:",Fore.CYAN+str(Data1["data"]["usageType"])+Fore.RESET)
                print(Fore.LIGHTMAGENTA_EX+"\nFuentes:"+Fore.RESET,"\n 1) IP Abuse DB:",M1,"Puntuacion Individual de riesgo:",PuntuacionAIPADBIP1,"\n 2) IP Quality Score:",M2,"Puntuacion Individual:",PuntuacionAPIPQ1,"\n 3) Virus Total:",M3,"Puntuacion Individual:",PuntuacionAIPVT1)
                print(Fore.LIGHTMAGENTA_EX+"\nCambios de Nombre:\n"+Fore.RESET,"El host ha cambiado de nombre:",CND,", un total de:","No detectado","\n",CND1,"\n",CND2)
                print(Fore.LIGHTMAGENTA_EX+"\nURLs y Muestras Descargadas:"+Fore.RESET,"\n Urls en esta IP Detectadas como maliciosas:","No detectado","\n Muestras descargadas detectadas:",DDS2)

            #Trabajar guardar data en un archivo            
            """ 
            p1="El análisis de la direccion",IP1,"arrojo los siguientes resultados:"
            with open("Resultados del analisis.json", "w") as a:
                json.dump(p1,a)
            """
        
            input("\n Presione cualquier tecla para continuar")
            break
        elif IPR=="Privada":
            print("La IP pertenece a una Red Privada")
            break

#Analisis de subnet
def RASU1(Red,Data4):
    try:
        if(Data4["reportedAddress"]<int(0)):
            SUR=AdspaceRASU(Data4)
            NumTohS=NumToHS(Data4)
            SumReport=PasHost(Data4)
            PutuacionSub=(NivRieSu(Data4))
            #Evaluar si es publica o privada con manejo de errores por si el usuario pone algo incorrecto
            while True:
                if(SUR=="Publica"):
                    #Obtener data de una ip como dominio, tipo de uso etc.
                    IP1=(Data4["data"]["reportedAddress"][0]["ipAddress"])
                    Data2=AIQSIP(IP1)
                    
                    ISPred=Data2['ISP']
                    CountCode=Data2["country_code"]
                    RegiPai=Data2["region"]
                    CitPai=Data2['city']
                    
                    if(Data2["bot_status"]==True): bot=Fore.RED+"si"+Fore.RESET
                    else: bot=Fore.GREEN+"No"+Fore.RESET
                    
                    if(Data2["proxy"]==True): proxy=Fore.RED+"si"+Fore.RESET
                    else: proxy=Fore.GREEN+"No"+Fore.RESET
                    
                    if(Data2["active_vpn"]==True): vpn=Fore.RED+"si"+Fore.RESET
                    else: vpn=Fore.GREEN+"No"+Fore.RESET

                    if(Data2["active_tor"]==True): tor=Fore.RED+"si"+Fore.RESET
                    else: tor=Fore.GREEN+"No"+Fore.RESET
                    
                    if(len(Data4["data"]['reportedAddress'])<5): ReporAd=Fore.GREEN+str(len(Data4["data"]['reportedAddress']))+Fore.RESET
                    else: ReporAd=Fore.RED+str(len(Data4["data"]['reportedAddress']))+Fore.RESET
                    
                    print(Fore.BLUE+"El análisis de la red(subnet)"+Fore.RESET,Red,Fore.BLUE+"arrojo los siguientes resultados:"+Fore.RESET,"\n a) La red es de uso: Publico\n b) La primera posible direccion es",Fore.CYAN+str(Data4["data"]["minAddress"])+Fore.RESET,"y la ultima",Fore.CYAN+str(Data4["data"]['maxAddress'])+Fore.RESET,"\n c) El numero total de posibles host es:",Fore.CYAN+str(Data4["data"]["numPossibleHosts"])+Fore.RESET,"\n d) Del Rango antes mencionado",ReporAd,"IPs tienen reportes\n e) El porcentaje de IPs reportadas del rango equivale a un",NumTohS,"%","\n f) La sumatoria de los reportes realizados a esta red:",SumReport,"\n g) El nivel de riesgo es:",PutuacionSub)
                    print("\n 1) Informacion General: \n ",Fore.BLUE+"ISP:"+Fore.RESET,ISPred,Fore.BLUE+"Pais Codigo:"+Fore.RESET,CountCode,Fore.BLUE+"Region:"+Fore.RESET,RegiPai,Fore.BLUE+"Ciudad:"+Fore.RESET,CitPai,"\n  Es una conexion tipo,",Fore.BLUE+" Proxy:"+Fore.RESET,proxy,Fore.BLUE+"Vpn:"+Fore.RESET,vpn,Fore.BLUE+"Nodo Tor:"+Fore.RESET,tor,Fore.BLUE+"Bot:"+Fore.RESET,bot)
                    break
        else:
            print("La red no tiene reportes registrados")
            
    except KeyError:
        IP1=(Data4["data"]["minAddress"])
        Data2=AIQSIP(IP1)
                
        ISPred=Data2['ISP']
        CountCode=Data2["country_code"]
        RegiPai=Data2["region"]
        CitPai=Data2['city']
                    
        if(Data2["bot_status"]==True): bot=Fore.RED+"si"+Fore.RESET
        else: bot=Fore.GREEN+"No"+Fore.RESET
                    
        if(Data2["proxy"]==True): proxy=Fore.RED+"si"+Fore.RESET
        else: proxy=Fore.GREEN+"No"+Fore.RESET
                    
        if(Data2["active_vpn"]==True): vpn=Fore.RED+"si"+Fore.RESET
        else: vpn=Fore.GREEN+"No"+Fore.RESET

        if(Data2["active_tor"]==True): tor=Fore.RED+"si"+Fore.RESET
        else: tor=Fore.GREEN+"No"+Fore.RESET
        
        print(Fore.BLUE+"El análisis de la red(subnet)"+Fore.RESET,Red,Fore.BLUE+"arrojo los siguientes resultados:"+Fore.RESET,"\n a) La red es de uso: Publico\n b) La primera posible direccion es",Fore.CYAN+str(Data4["data"]["minAddress"])+Fore.RESET,"y la ultima",Fore.CYAN+str(Data4["data"]['maxAddress'])+Fore.RESET,"\n c) El numero total de posibles host es:",Fore.CYAN+str(Data4["data"]["numPossibleHosts"])+Fore.RESET,"\n d) Del Rango antes mencionado",Fore.GREEN+"0"+Fore.RESET,"IPs tienen reportes\n e) El porcentaje de IPs reportadas del rango equivale a un",Fore.GREEN+"0%"+Fore.RESET,"\n f) La sumatoria de los reportes realizados a esta red:",Fore.GREEN+"0"+Fore.RESET,"\n g) El nivel de riesgo es:",Fore.GREEN+"Bajo"+Fore.RESET)
        
        print("\n 1) Informacion General: \n ",Fore.BLUE+"ISP:"+Fore.RESET,ISPred,Fore.BLUE+"Pais Codigo:"+Fore.RESET,CountCode,Fore.BLUE+"Region:"+Fore.RESET,RegiPai,Fore.BLUE+"Ciudad:"+Fore.RESET,CitPai,"\n  Es una conexion tipo,",Fore.BLUE+" Proxy:"+Fore.RESET,proxy,Fore.BLUE+"Vpn:"+Fore.RESET,vpn,Fore.BLUE+"Nodo Tor:"+Fore.RESET,tor,Fore.BLUE+"Bot:"+Fore.RESET,bot)
        
#Crear Lista con ips con altos, medios y bajos reportes por separado 
def RASAL(Data4):
    N=0
    Alto=[]
    PosiHost=int(Data4["data"]["numPossibleHosts"])
    
    while N < (PosiHost)+1:
        try:
            if((Data4["data"]['reportedAddress'][N]['numReports'])>50):
                Alto.append(Data4["data"]['reportedAddress'][N]["ipAddress"])
                N=N+1
            else:
                return Alto
        except IndexError:
            break
    else:
        return 0
    
def RASME(Data4):
    N=0
    Medio=[]
    PosiHost=int(Data4["data"]["numPossibleHosts"])
    
    while N < (PosiHost)+1:
        try:
            if((Data4["data"]['reportedAddress'][N]['numReports'])>10 and (Data4["data"]['reportedAddress'][N]['numReports'])<50):
                Medio.append(Data4["data"]['reportedAddress'][N]["ipAddress"])
                N=N+1
            else:
                return Medio
        except IndexError:
            break
    else:
        return 0
    
def RASBA(Data4):
    N=0
    Bajo=[]
    PosiHost=int(Data4["data"]["numPossibleHosts"])
    
    while N < (PosiHost)+1:
        try:
            if((Data4["data"]['reportedAddress'][N]['numReports'])<=10):
                Bajo.append(Data4["data"]['reportedAddress'][N]["ipAddress"])
                N=N+1
            else:
                return Bajo
        except IndexError:
            break
    else:
        return 0

def RASTO(Data4):
    N=0
    Todo=[]
    PosiHost=int(Data4["data"]["numPossibleHosts"])
    
    while N < (PosiHost)+1:
        try:
            if((Data4["data"]['reportedAddress'][N]['numReports'])>1):
                Todo.append(Data4["data"]['reportedAddress'][N]["ipAddress"])
                N=N+1
            else:
                return Todo
        except IndexError:
            break
    else:
        return 0
    

#Menu de opciones de la opcion de analisis de subnet(red)
def RASU11(Data4):
    print(Fore.GREEN+"1-Bajos Reportes, son las que contienen 10 o menos reportes."+Fore.RESET)
    print(RASBA(Data4))
    input("Continuar con su investigacion?")
    Limpiar()

def RASU12(Data4):
    print(Fore.LIGHTRED_EX+"2-Medio-Son las que contienen entre 10 y 50 reportes."+Fore.RESET)
    print(RASME(Data4))
    input("Continuar con su investigacion?")
    Limpiar()

def RASU13(Data4):
    print(Fore.RED+"3-Altos reportes mas de 50 reportes"+Fore.RESET)
    print(RASAL(Data4))
    input("Continuar con su investigacion?")
    Limpiar()   