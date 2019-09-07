#!/usr/bin/env python3

import ipaddress
import time
import subprocess
from sys import exit
from os import path
from argparse import ArgumentParser
import yaml
import re


parser = ArgumentParser(description="Generate signed ROA requests for ARIN portal")

parser.add_argument("-i", "--interactive", dest='i', action='store_true',
                    help="run interactively (default is no)")

parser.add_argument("-r", "--ROAinfo", dest="r", metavar="",
                    action="store", default="ROAinfo.yml",
                    help="specify an alternate file for ROA info\n"
                         "(default=ROAinfo.yml)")

args = parser.parse_args()

interactive = args.i
ROAinfoFile = args.r


def getROAdetails():
    '''
    interactively get info needed to create the ROA request line
    :return: ASN, ROAname, prefixFile, vStart, vEnd, privKey
    '''
    goodInterval = False
    pfxfileExists = False
    keyfileExists = False
    today = time.strftime('%m-%d-%Y')
    tempdict = {}
    ASN = int(input("ASN: "))
    ROAname = str(input("ROA Name: "))
    while not pfxfileExists:
        prefixFile = str(input("Name of file containing list of prefixes (default = prefixes): ") or "prefixes")
        pfxfileExists = path.exists(prefixFile)
    vStart = str(input("Validity start date (MM-DD-YYY)(default = today {}) ".format(today)) or today)
    while not goodInterval:
        vEnd = str(input("Validity end date (MM-DD-YYY) ".format(today)))
        if time.strptime(vEnd, "%m-%d-%Y") <= time.strptime(vStart, "%m-%d-%Y"):
            print("End date must but at least one day after start date")
        else:
            goodInterval = True
    while not keyfileExists:
        privateKeyFile = str(input("Private Key to sign request (default = privkey.pem): ") or "privkey.pem")
        keyfileExists = path.exists(privateKeyFile)
    tempdict['ASN'] = ASN
    tempdict['ROAname'] = ROAname
    tempdict['prefixFile'] = prefixFile
    tempdict['vStart'] = vStart
    tempdict['vEnd'] = vEnd
    tempdict['privateKeyFile'] = privateKeyFile
    return tempdict


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


def readYML():
    """
    read YML file to gather info about ROAs to create
    :return: ROAdata (dict, keys:ROAName, Prefix, Version, OriginAS, EndDate, StartDate, Keyfile)
    """
    with open(ROAinfoFile, 'r') as infile:
        rinfo = yaml.load(infile)
    return rinfo


def preProcessPrefixes(prefixList):
    """
    preprocess the prefix list.
    because ROAs allow option max length on a prefix (to allow for a range of mask values), this function
    will detect if that option is in use and validate both the shortest and longest prefixes to ensure
    they're valid.
    This temporary list will be run through 'validatePrefixList' to ensure we're working with valid data
    in the event that there are *any* invalids, they'll be noted, and the whole script will bail
    :param prefixList:
    :return: processedPrefixList
    """
    processedPrefixList = []
    for entry in prefixList:
        components = re.split("[/ -]", entry)
        if len(components) == 2:                                # no mask length option
            processedPrefixList.append(components[0] + '/' + components[1])
        else:                                                   # optional masklength
            processedPrefixList.append(components[0] + '/' + components[1])           # base network
            processedPrefixList.append(components[0] + '/' + components[4])           # max length prefix
    validList, invalidList = validatePrefixList(processedPrefixList)
    if len(invalidList) > 0:
        print("***Detected {} invalid prefixes.  Bailing....".format(len(invalidList)))
        for badline in invalidList:
            print(badline)
        print("***Detected {} invalid prefixes.  Bailing....".format(len(invalidList)))
        exit(1)
    print("{} valid prefixes will be included in the ROA request.".format(len(validList)))
    return


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


def generateROAreqLine(inDict):
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
    :param dict containing ASN, ROAname, prefixFile, vStart, vEnd, prefixlist
    :return: roareq(str)
    '''
    epochtime = int(time.time())
    # create the static portion of the ROA request line
    roareq = "{}|{}|{}|{}|{}|{}|".format(inDict['Version'], epochtime, inDict['ROAName'], inDict['OriginAS'],
                                         inDict['StartDate'], inDict['EndDate'])
    for network in inDict['Prefixes']:
        roareq += '{}|{}||'.format(network.split('/')[0], network.split('/')[1])
    return roareq


def createSignedRequest(roaReqLine, ROAName, privKey):
    '''
    generate and convert the signature
    combine signature with ROA request line to form fully formatted signed request
    :param roaReqLine:
    :param privKey
    :return: string which is the fully formed, signed request
    '''
    filename = ROAName + '_' + time.strftime("%d%b%Y-%H%M").upper() + '.txt'
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
    if interactive:
        allInfo = getROAdetails()
        # will need to create dictionary at this point to match what is read from the YML file
        allInfo['Prefixes'] = getPrefixList(allInfo['prefixFile'])
    else:
        allInfo = readYML()
    # preprocess prefixes to catch lines with max length
    preProcessPrefixes(allInfo['Prefixes'])
    roaRequstData = generateROAreqLine(allInfo)
    createSignedRequest(roaRequstData, allInfo['ROAName'], allInfo['Keyfile'])


main()
