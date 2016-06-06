import merakiapi
from ciscoAsaExport import exportAsaProfile

apikey = 'xxxxx'
organizationid = 'xxxxx'

vpn = merakiapi.getnonmerakivpnpeers(apikey, organizationid)
subnets = merakiapi.getvpnpeers(apikey, merakiapi.getNetworkbyName('Home',apikey, organizationid))

def getVpnSubnets(subnets):
    subn = []
    for sub in subnets['subnets']:
        if sub['useVpn']==True:
            subn.append(sub['localSubnet'])
    return subn

exportAsaProfile(vpn, getVpnSubnets(subnets))




