from colorama import init,Fore,Back,Style
init()

#Manejo de errores para la resolutions
def ResolutVT(Data3):
    try:
        Reso=int(len(Data3["resolutions"]))
        return Reso
    except KeyError:
        Reso=int(0)
        return Reso

#Funciones para el analisis de datos
def PuntuacionAIPADBIP(Data1):
    PuntuacionDeAbuso=int(Data1["data"]["abuseConfidenceScore"])
    
    while(int(PuntuacionDeAbuso)>0):
        if (int(PuntuacionDeAbuso)<40):
            PuntuacionDeAbuso=Fore.LIGHTGREEN_EX+"2-Bajo"+Fore.RESET
            return(PuntuacionDeAbuso)
        elif (int(PuntuacionDeAbuso)<75):
            PuntuacionDeAbuso=Fore.RED+"3-Medio"+Fore.RESET
            return(PuntuacionDeAbuso)
        elif (int(PuntuacionDeAbuso)<101):
             PuntuacionDeAbuso=Fore.RED+"4-Alto"+Fore.RESET
             return(PuntuacionDeAbuso)
    else: 
        PuntuacionDeAbuso=Fore.GREEN+"1-Nulo"+Fore.RESET 
        return(PuntuacionDeAbuso)

#Puntuacion de fraude ip quality score
def PuntuacionAPIPQ(Data2):
    PuntuacionDeAbuso2=int(Data2["fraud_score"])
    
    while(int(PuntuacionDeAbuso2)>0):
        if (int(PuntuacionDeAbuso2)<40):
            PuntuacionDeAbuso2=Fore.LIGHTGREEN_EX+"2-Bajo"+Fore.RESET
            return(PuntuacionDeAbuso2)
        elif (int(PuntuacionDeAbuso2)<75):
            PuntuacionDeAbuso2=Fore.RED+"3-Medio"+Fore.RESET
            return(PuntuacionDeAbuso2)
        elif (int(PuntuacionDeAbuso2)<101):
             PuntuacionDeAbuso2=Fore.RED+"4-Alto"+Fore.RESET
             return(PuntuacionDeAbuso2)
    else: 
        PuntuacionDeAbuso2=Fore.GREEN+"1-Nulo"+Fore.RESET 
        return(PuntuacionDeAbuso2)

#Puntuacion de fraude Virus total
def PuntuacionAIPVT(Data3):
    try:
        PuntuacionDeAbuso3=int(len(Data3["detected_urls"]))
        
        while(PuntuacionDeAbuso3>1):
            if (PuntuacionDeAbuso3)<3:
                PuntuacionDeAbuso3=Fore.LIGHTGREEN_EX+"2-Bajo"+Fore.RESET
                return(PuntuacionDeAbuso3)
            elif (PuntuacionDeAbuso3)<5:
                PuntuacionDeAbuso3=Fore.RED+"3-Medio"+Fore.RESET
                return(PuntuacionDeAbuso3)
            elif (PuntuacionDeAbuso3)>5:
                PuntuacionDeAbuso3=Fore.RED+"4-Alto"+Fore.RESET
                return(PuntuacionDeAbuso3)
        else: 
            PuntuacionDeAbuso3=Fore.GREEN+"1-Nulo"+Fore.RESET 
            return(PuntuacionDeAbuso3)
    except KeyError:
        PuntuacionDeAbuso3="No detectado"

#Color para el numero de usuarios que reportaron
def NumUserIpAbuseDb(Data1):
    CantidadU=Data1["data"]['numDistinctUsers']
    while(int(CantidadU)>0):
        if (int(CantidadU)<3):
            A=Data1["data"]['numDistinctUsers']
            B=Fore.LIGHTGREEN_EX+"(Bajo)"+Fore.RESET
            CantidadU=A,B
            return CantidadU
        elif (int(CantidadU)<6):
            A=Data1["data"]['numDistinctUsers']
            B=Fore.LIGHTRED_EX+"(Medio)"+Fore.RESET
            CantidadU=A,B
            return CantidadU
        elif (int(CantidadU)<9):
            A=Data1["data"]['numDistinctUsers']
            B=Fore.LIGHTRED_EX+"(Alto)"+Fore.RESET
            CantidadU=A,B
            return CantidadU
        elif (int(CantidadU)>9):
            A=Data1["data"]['numDistinctUsers']
            B=Fore.RED+"(Masivo)"+Fore.RESET
            CantidadU=B
            return CantidadU   
        else:
            CantidadU=Data1["data"]['numDistinctUsers'],","+Fore.GREEN+"-Nulo"+Fore.RESET 
            return CantidadU

#Color para el numero de reportes que reportaron
def NumReportIpAbuseDb(Data1):
    CantidadR=Data1["data"]['totalReports']
    while(int(CantidadR)>0):
        if (int(CantidadR)<10):
            A=Data1["data"]['totalReports']
            B=Fore.LIGHTGREEN_EX+"(Bajo)"+Fore.RESET
            CantidadR=A,B
            return CantidadR
        elif (int(CantidadR)<20):
            A=Data1["data"]['totalReports']
            B=Fore.LIGTRED_EX+"(Medio)"+Fore.RESET
            CantidadR=A,B
            return CantidadR
        elif (int(CantidadR)<30):
            A=Data1["data"]['totalReports']
            B=Fore.LIGHTRED_EX+"(Alto)"+Fore.RESET
            CantidadR=A,B
            return CantidadR
        elif (int(CantidadR)>40):
            A=Data1["data"]['totalReports']
            B=Fore.RED+"(Masivo)"+Fore.RESET
            CantidadR=B
            return CantidadR   
        else:
            CantidadR=Data1["data"]['totalReports'],","+Fore.GREEN+"-Nulo"+Fore.RESET 
            return CantidadR

#Informacion del codigo el pais en azul
def PaisIPAbuseDB(Data2):
    #"Codigo del pais",Data2["country_code"],", region",Data2["region"],", city",Data2["city"]
    A=(Fore.CYAN+"Codigo del pais "+Fore.RESET)
    B=(Fore.CYAN+" Region "+Fore.RESET)
    C=(Fore.CYAN+" City "+Fore.RESET)
    D=str(Data2["country_code"])
    E=str(Data2["region"])
    F=str(Data2["city"])
    GeograIP=A+D+B+E+C+F
    return GeograIP

#Cambios de Nombre VT
def CDNombre(CDV):
    while(CDV>1):
        if(CDV<3):
            CND=Fore.GREEN+"Si, 1-Pocos"+Fore.RESET
            return(CND)
        elif(CDV<5):
            CND=Fore.LIGHTGREEN_EX+"Si, 2-Frecuente"+Fore.RESET
            return(CND)
        elif(CDV<8):
            CND=Fore.LIGHTRED_EX+"Si- 3-Muy frecuentes"+Fore.RESET
            return(CND)
        elif(CDV>8):
            CND=Fore.RED+"Si- 4-Masivo"+Fore.RESET
            return(CND)
    else:
        CND=Fore.MAGENTA+"No tiene registros"+Fore.RESET
        return(CND)    

#Saber si la red es privada o publica
def AdspaceRASU(Data4):
    try:
        if(Data4["data"]["addressSpaceDesc"]=="Internet"):
            SUR="Publica"
            return SUR
        else:
            SUR="Privada"
            return SUR
    except KeyError:
        SUR="Red no valida"
        return SUR

#Calcular el total de host con reportes recientes:
def NumToHS(Data4):
    
    Total=int(Data4["data"]['numPossibleHosts'])
    NumTohs=int(len(Data4["data"]['reportedAddress']))
    PorcNum=round((NumTohs/Total)*100)
    return PorcNum

#Calcular el numero total de reportes que tiene la red
def PasHost(Data4):
    N=0
    Sum=0
    PosiHost=int(Data4["data"]["numPossibleHosts"])
    while N < PosiHost:
        try:
            Hosts=int(Data4["data"]['reportedAddress'][N]['numReports'])
            Sum=Sum+Hosts
            N=N+1
        except IndexError:
            return Sum

    else:
        return Sum

#Nivel de riesgo red
def NivRieSu(Data4):
    IpsReport=int(len(Data4["data"]['reportedAddress']))
    SumaDeReportes=PasHost(Data4)
    PorcDeIP=NumToHS(Data4)
    while True:
        if(IpsReport<int(1) and PorcDeIP<int(5) and SumaDeReportes<int(15)):
            PuntuacionRed="0-Baja"
        elif(IpsReport<int(5) and int(PorcDeIP)<int(5) and SumaDeReportes<int(200)):
            PuntuacionRed="1-Baja"
            return PuntuacionRed
        elif(IpsReport<int(8) and int(PorcDeIP)<int(10) and SumaDeReportes<int(250)):
            PuntuacionRed="2-Baja"
            return PuntuacionRed
        elif(IpsReport<int(13) and int(PorcDeIP)<int(17) and SumaDeReportes<int(350)):
            PuntuacionRed="3-Media"
            return PuntuacionRed
        elif(IpsReport<int(19) and int(PorcDeIP)<int(20) and SumaDeReportes<int(600)):
            PuntuacionRed="4-Media"
            return PuntuacionRed
        elif(IpsReport<int(25) and int(PorcDeIP)<int(25) and SumaDeReportes<int(2000)):
            PuntuacionRed="5-Alto"
            return PuntuacionRed
        elif(IpsReport<32 and int(PorcDeIP)<30 and SumaDeReportes<int(5000)):
            PuntuacionRed="6-Alto"
            return PuntuacionRed
        elif(IpsReport<40 and int(PorcDeIP)<30 and SumaDeReportes<int(10000)):
            PuntuacionRed="7-Alto"
            return PuntuacionRed
        elif(IpsReport<55 and int(PorcDeIP)<50 and SumaDeReportes<int(15000)):
            PuntuacionRed="8-Extremo"
            return PuntuacionRed
        elif(IpsReport<75 and int(PorcDeIP)<75 and SumaDeReportes<int(20000)):
            PuntuacionRed="9-Extremo"
            return PuntuacionRed
        elif(IpsReport>10 and int(PorcDeIP)>10 and SumaDeReportes<int(20000)):
            PuntuacionRed="10-Extremo(Pocas IPs, Muchos reportes)"
            return PuntuacionRed
        elif(IpsReport<20 and int(PorcDeIP)<20 and SumaDeReportes>int(25000)):
            PuntuacionRed="10-Extremo(Considerables IPs, Muchos reportes)"
            return PuntuacionRed
        elif(IpsReport>30 and int(PorcDeIP)>10 and SumaDeReportes>int(30000)):
            PuntuacionRed="10-Extremo(Masivas IPs, Muchos reportes)"
            return PuntuacionRed
        elif(IpsReport>74 and int(PorcDeIP)>74 and SumaDeReportes>int(30000)):
            PuntuacionRed="10-Extremo"
            return PuntuacionRed
        #Sino cumple con ninguna de estas condiciones
        else:
            PuntuacionRed="No calculado"
            return PuntuacionRed

    
        

    
    
    