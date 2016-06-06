from socket import inet_ntoa
from struct import pack

def calcDottedNetmask(mask):
    bits = 0xffffffff ^ (1 << 32 - mask) - 1
    return inet_ntoa(pack('>I', bits))

def _convertCiscoCrypt(crypt):
    return str(crypt).replace(' ', '-',1)

def _convertCiscoHash(hash):
    return str(hash).replace('1','',1)

def _convertCiscoP2hash(hash):
    p2hash = {
        'hmac_sha1': 'esp-sha-hmac',
        'hmac_md5' : 'esp-md5-hmac',
    }
    return p2hash.get(hash, hash)

def _convertCiscoP2Crypt(crypt):
    p2Crypt = {
        'aes 128': 'esp-aes-128',
        'aes 192': 'esp-aes-192',
        'aes 256': 'esp-aes-256',
        '3des': 'esp-3des-hmac',
        'des': 'esp-des-hmac',
    }
    return p2Crypt.get(crypt, crypt)

def exportAsaProfile(exportedvpn, subnets):
    num = 0
    allAcls = []
    for v in exportedvpn:
        ciscoP1Crypt = _convertCiscoCrypt(v['ipsec_policies']['config']['phase1_crypt_algo'])
        ciscoP1Hash = _convertCiscoHash(v['ipsec_policies']['config']['phase1_hash_algo'])
        ciscoP2Crypt = _convertCiscoP2Crypt(v['ipsec_policies']['config']['phase2_crypt_algo'][0])
        ciscoP2Hash = _convertCiscoP2hash(v['ipsec_policies']['config']['phase2_auth_algo'][0])
        vpnProfile = """isakmp policy 1
    authentication pre-share
    encryption {p1enc}
    hash {p1hash}
    group {p1group}
    lifetime {p1lifetime}
!""".format(p1enc=ciscoP1Crypt,p1hash=ciscoP1Hash,p1group=v['ipsec_policies']['config']['dh_group'],p1lifetime=v['ipsec_policies']['config']['phase1_lifetime'])
    vpnP2Profile = """crypto ipsec transform-set meraki {p2crypt} {p2hash}""".format(p2crypt=ciscoP2Crypt, p2hash=ciscoP2Hash )
    print(vpnProfile)
    print(vpnP2Profile)
    print('!')
    for sn in subnets:
        num+= 1
        srcNet = str(sn).split('/')[0]
        srcMask = calcDottedNetmask(int((sn).split('/')[1]))
        dstMask = calcDottedNetmask(int((v['privateSubnets'][0]).split('/')[1]))
        dstNet = str(v['privateSubnets'][0]).split('/')[0]
        acl = """access-list meraki{num} extended permit ip {destIp} {destMask} {sourceIp} {sourceMask}""".format(num=num, sourceIp=srcNet, sourceMask=srcMask, destIp=dstNet, destMask=dstMask)
        allAcls.append('meraki' + str(num),)
        print(acl)
    tunnelGroup = """tunnel-group {remoteIP} type ipsec-l2l
tunnel-group {remoteIP} ipsec-attributes
    pre-shared-key {secret}""".format(remoteIP=v['publicIp'], secret=v['secret'])
    print('!')
    print(tunnelGroup)
    print('!')
    num = 0
    for acl in allAcls:
        num += 1
        cryptoMap = """crypto map L2L {num} match address {acl}
crypto map L2L {num} set peer {remoteIP}
crypto map L2L {num} set transform-set meraki
crypto map L2L interface outside""". format(acl=acl, num=num, remoteIP=v['publicIp'])
    print(cryptoMap)
    print('!')