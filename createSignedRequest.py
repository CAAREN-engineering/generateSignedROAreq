#!/usr/bin/env python3

import ipaddress
import time
import subprocess
import os
from argparse import ArgumentParser
import yaml
import re


parser = ArgumentParser(description="Generate signed ROA requests for ARIN portal")

parser.add_argument("-r", "--ROAinfo", dest="r", metavar="",
                    action="store", default="ROAinfo.yml",
                    help="specify an alternate file for ROA info\n"
                         "(default=ROAinfo.yml)")

args = parser.parse_args()

ROAinfoFile = args.r


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
        os._exit(1)
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
    for entry in inDict['Prefixes']:
        components = re.split("[/ -]", entry)
        if len(components) == 2:                                # no mask length option
            roareq += '{}|{}||'.format(components[0], components[1])
        else:                                                   # optional masklength
            roareq += '{}|{}|{}|'.format(components[0], components[1], components[4])
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
    allInfo = readYML()
    # preprocess prefixes to catch lines with max length
    preProcessPrefixes(allInfo['Prefixes'])
    roaRequstData = generateROAreqLine(allInfo)
    createSignedRequest(roaRequstData, allInfo['ROAName'], allInfo['Keyfile'])


main()
