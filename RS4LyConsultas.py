import requests
import json


#Funciones para consultas de ip Virus Total
def AVTIP(IP1):
    Api="Api Key Virus Total"
    LinkDeLaApi="https://www.virustotal.com/vtapi/v2/ip-address/report"
    he={'apikey': Api, 'ip':IP1}
    DataDeVT2=requests.get(url=LinkDeLaApi, params=he)
    #Activar este print si quiere ver el codigo de estatus (200=correcta)
    print(DataDeVT2)
    DataDeVT2=(DataDeVT2.json())
    return(DataDeVT2)

#Funcion de consultas ip en ipabusedb
def AIPADBIP(IP1):
    Api="Api Key IP Abuse DB"
    LinkDeLaApi="https://api.abuseipdb.com/api/v2/check"
    IP1={'ipAddress': IP1}
    he={"Accept":"application\json","key":Api}
    DataDeIpAbuseDb1=requests.get(url=LinkDeLaApi,headers=he,params=IP1)
    #Activar este print si quiere ver el codigo de estatus (200=correcta)
    #print(DataDeIpAbuseDb1)
    DataDeIpAbuseDb1=json.loads(DataDeIpAbuseDb1.text)
    return(DataDeIpAbuseDb1)

#Funcion de consultas ip en ipqualityscore
def AIQSIP(IP1):
    Api="Api Key IP Quality Score/"
    LinkDeLaApi="https://ipqualityscore.com/api/json/ip/"
    LinkFinal=LinkDeLaApi+Api+IP1
    DataDeIpQualityScore1=requests.get(url=LinkFinal)
    #Activar este print si quiere ver el codigo de estatus (200=correcta)
    #print(DataDeIpQualityScore1)
    DataDeIpQualityScore1=json.loads(DataDeIpQualityScore1.text)
    return(DataDeIpQualityScore1)

#funciones de consulta ipqualityscore para analizar URLs
def AIQSURL(URL):
    Api="Api Key IP Quality Score"
    LinkDeLaApi="https://ipqualityscore.com/api/json/url/"
    LinkFinal=LinkDeLaApi+Api+URL
    DataDeIpQualityScore2=requests.get(url=LinkFinal)
    #Activar este print si quiere ver el codigo de estatus (200=correcta)
    #print(DataDeIpQualityScore2)
    DataDeIpQualityScore2=json.loads(DataDeIpQualityScore2.text)
    return(DataDeIpQualityScore2)



def AIPADBSU(Red):
    Api="Api Key IP Abuse DB"
    LinkDeLaApi="https://api.abuseipdb.com/api/v2/check-block"
    Red={'network': Red}
    he={"Accept":"application\json","key":Api}
    DataDeIpAbuseDb2=requests.get(url=LinkDeLaApi,headers=he,params=Red)
    #Activar este print si quiere ver el codigo de estatus (200=correcta)
    #print(DataDeIpAbuseDb2)
    DataDeIpAbuseDb2=json.loads(DataDeIpAbuseDb2.text)
    return(DataDeIpAbuseDb2)








#Funcion de consulta de url en Virus Total
def AVTURL(URL):
    Api="Api Key Virus Total"
    LinkDeLaApi="https://www.virustotal.com/vtapi/v2/url/report"
    he={'apikey': Api, 'resource':URL}
    DataDeVT1=requests.get(url=LinkDeLaApi, params=he)
    #Activar este print si quiere ver el codigo de estatus (200=correcta)
    #print(DataDeVT1)
    DataDeVT1=(DataDeVT1.json())
    return(DataDeVT1)

#Funcion del consulta de subnet en ipabusedb
def AIPADBSU(Red):
    Api="Api Key IP Abuse DB"
    LinkDeLaApi="https://api.abuseipdb.com/api/v2/check-block"
    Red={'network': Red}
    he={"Accept":"application\json","key":Api}
    DataDeIpAbuseDb2=requests.get(url=LinkDeLaApi,headers=he,params=Red)
    #Activar este print si quiere ver el codigo de estatus (200=correcta)
    #print(DataDeIpAbuseDb2)
    DataDeIpAbuseDb2=json.loads(DataDeIpAbuseDb2.text)
    return(DataDeIpAbuseDb2)

