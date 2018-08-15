#!/usr/bin/python3

import ipaddress
import time
import subprocess
from sys import exit


def getROAdetails():
    '''
    interactively get info needed to create the ROA request line
    :return: ASN, ROAname, prefixFile, vStart, vEnd, privKey
    '''
    goodInterval = False
    today = time.strftime('%m-%d-%Y')
    ASN = int(input("ASN: "))
    ROAname = str(input("ROA Name: "))
    prefixFile = str(input("Name of file containing list of prefixes (default = prefixes): ") or "prefixes")
    vStart = str(input("Validity start date (MM-DD-YYY)(default = today {}) ".format(today)) or today)
    while not goodInterval:
        vEnd = str(input("Validity end date (MM-DD-YYY) ".format(today)))
        if time.strptime(vEnd, "%m-%d-%Y") <= time.strptime(vStart, "%m-%d-%Y"):
            print("End date must but at least one day after start date")
        else:
            goodInterval = True
    privateKeyFile = str(input("Private Key to sign request (default = privkey.pem): ") or "privkey.pem")
    return ASN, ROAname, prefixFile, vStart, vEnd, privateKeyFile


def getPrefixList(file):
    '''
    process input list of prefixes
    read a file, strip the comments ('#'),
    :param file:
    :return: prefixes (list, no comments)
    '''
    with open(file) as f:
        prefixes = []
        for line in f:
            line = line.partition('#')[0]
            line = line.rstrip()
            if len(line) > 0:
                prefixes.append(line)
    return prefixes


def validatePrefixList(pfList):
    '''
    validate the list of prefixes
    normalize IPv6 to compressed form (because ARIN's parser currently doesn't support uncompressed v6 addrs)
    count the number of errors (if any)
    :param pfList:
    :return: valids, invalidPFlist
    '''
    validPrefixes = 0
    invalidPFlist = []
    for index, item in enumerate(pfList):
        try:
            ipaddress.ip_network(item)
            validPrefixes += 1
            if item.upper() != str(ipaddress.ip_network(item)).upper():
                pfList[index] = str(ipaddress.ip_network(item)).upper()
        except ValueError:
            invalidPFlist.append(item)
    valids = set(pfList) - set(invalidPFlist)
    return valids, invalidPFlist


def generateROAreqLine(ASN, ROAname, prefixFile, vStart, vEnd, prefixlist):
    '''
    generate the ROA request.  in a manually signed ROA request, this is the single list that gets signed
    by ssl.  it is a pipe (|) separated line in the following format:
        A|B|C|D|E|F|G|H|I|J|
        A = version number (always 1)
        B = time stamp in UNIX epoch
        C = ROA name
        E = Origin AS
        F = validity start
        G = validity end
        H = prefix*
        I = mask*
        J = (optional) max length*
        max length can be blank
        * multiple prefixes can be included in the same ROA, just keep appending these fields with pipe separators
        A request line for a single prefix (no max field) might look like:
        1|1340135296|My First ROA|1234|05-25-2011|05-25-2012|10.0.0.0|8||
        A request list for multiple prefixes (again, no max field) might look like:
        1|1533652213|multipleROA|4901|07-22-2015|07-22-2025|2620:106:C000::|44||2620:106:c00f:fd00::|64||
    :param ASN, ROAname, prefixFile, vStart, vEnd, prefixlist
    :return: roareq(str)
    '''
    epochtime = int(time.time())
    # create the static portion of the ROA request line
    roareq = "1|{}|{}|{}|{}|{}|".format(epochtime, ROAname, ASN, vStart, vEnd)
    for network in prefixlist:
        roareq += '{}|{}||'.format(network.split('/')[0], network.split('/')[1])
    return roareq


def createSignedRequest(roaReqLine, ROAname, privKey):
    '''
    generate and convert the signature
    combine signature with ROA request line to form fully formatted signed request
    :param roaReqLine:
    :param privKey
    :return: string which is the fully formed, signed request
    '''
    filename = ROAname + '_' + time.strftime("%d%b%Y-%H%M") + '.txt'
    # write the ROA request line to a file so we can sign it
    with open('roadata.txt', 'w') as roadata:
        roadata.write(roaReqLine)
    #    roadata.write('\n')
    # sign the ROA request line and convert the signature format
    subprocess.call(["openssl", "dgst", "-sha256", "-sign", privKey, "-keyform", "PEM", "-out", "signature",
                     "roadata.txt"])
    with open('sig_base64', 'w') as outfile:
        subprocess.call(["openssl", "enc", "-base64", "-in", "signature"], stdout=outfile)
    # combine the various pieces to make a complete signed request
    with open(filename, 'w') as final:
        final.write('-----BEGIN ROA REQUEST-----\n')
        with open('roadata.txt', 'r') as roadata:
            for line in roadata:
                final.write(line)
        final.write('-----END ROA REQUEST-----\n')
        final.write('-----BEGIN SIGNATURE-----\n')
        with open('sig_base64', 'r') as sig:
            for line in sig:
                final.write(line)
        final.write('-----END SIGNATURE-----\n')
    print("\n" + filename + " has been created.")
    # clean up temporary files
    subprocess.call(['rm', 'signature'])
    subprocess.call(['rm', 'sig_base64'])
    subprocess.call(['rm', 'roadata.txt'])


def main():
    ASN, ROAname, prefixFile, vStart, vEnd, privKey = getROAdetails()
    listofPrefixes = getPrefixList(prefixFile)
    validList, invalidList = validatePrefixList(listofPrefixes)
    if len(invalidList) > 0:
        print("***Detected {} invalid prefixes.  Bailing....".format(len(invalidList)))
        for badline in invalidList:
            print(badline)
        print("***Detected {} invalid prefixes.  Bailing....".format(len(invalidList)))
        exit(1)
    print("{} valid prefixes will be included in the ROA request.".format(len(validList)))
    roaRequstData = generateROAreqLine(ASN, ROAname, prefixFile, vStart, vEnd, validList)
    createSignedRequest(roaRequstData, ROAname, privKey)


main()
