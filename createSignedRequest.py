#!/usr/bin/env python3

from argparse import ArgumentParser
import ipaddress
import os
import re
import subprocess
import time
import yaml


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
    tvallist = []
    invalidlist = []
    print("Entering preProcessPrefixes with prefixList = {}".format(prefixList))
    for index, item in enumerate(prefixList):
        # remove any whitespace that may be in the entry, can happen especially when mask range is in use
        # this makes the result of split more predictable
        item = item.replace(" ", "")
        # split the line on '/' or '-' to see if we're dealing with a range of masks
        components = re.split("[/-]", item)
        if len(components) == 2:  # no range, only address + mask
            # we need to rebuild the prefix in case there spaces were removed.  in reality, at this point, for
            # an entry not using the mask range option, 'item' should be good enough, but rebuilding from the
            # components drives the point home
            reformattedprefix = components[0] + '/' + components[1]
            # print("{} {} no mask range".format(index, reformattedprefix))
            try:
                if ipaddress.ip_network(reformattedprefix).version == 4:  # we have a valid v4 prefix
                    # print("got valid v4")
                    tvallist.append(reformattedprefix)
                elif ipaddress.ip_network(reformattedprefix).version == 6:  # we have a valid v6 prefix
                    # print("got valid v6")
                    # need to use the output of ipaddress.ip_network because that compresses the v6 addr
                    # (removes leading zeros), which the ARIN portal doesn't understand
                    tvallist.append(str(ipaddress.ip_network(reformattedprefix)).upper())
            except ValueError:  # what ever entry is, it isn't valid
                # print("neither v4 nor v6")
                invalidlist.append(item)
        # this section is a bit more complicated- for networks where the mask range option is used
        # eg: 172.16.0.0/16-18, we need to temporarily deconstruct the entry, ensure that both the
        # base network (in this example 172.16.0.0/16) AND the prefix with the max length
        # (in this example 172.16.0.0/18) are both valid.
        # we then have to reconstruct the string from the validated components (especially in the case of v6, where
        # leading zeros need to be removed)
        if len(components) == 3:  # range option being used, we have address, base mask + max length
            # print("{} {} using mask range".format(index, item))
            basenetwork = components[0] + '/' + components[1]
            maxlennetwork = components[0] + '/' + components[2]
            reformattedprefixrange = components[0] + '/' + components[1] + '-' + components[2]
            # first, validate the base network
            try:
                if ipaddress.ip_network(basenetwork).version == 4:
                    # print("got valid v4")
                    if ipaddress.ip_network(
                            maxlennetwork).version == 4:  # checking that the prefix with max length mask is valid
                        # print("max len v4 is good, adding to temp list")
                        tvallist.append(reformattedprefixrange)
                elif ipaddress.ip_network(basenetwork).version == 6:
                    # print("got valid v6 for the base network")
                    if ipaddress.ip_network(
                            maxlennetwork).version == 6:  # checking that the prefix with max length mask is valid
                        # print("max len v4 is good, adding to temp list")
                        # need to reformat the v6 address to remove any leading zeros
                        reformattedv6rangeprefix = (
                                    str(ipaddress.ip_network(basenetwork)) + '-' + components[2]).upper()
                        tvallist.append(reformattedv6rangeprefix)
            except ValueError:
                # print("neither v4 nor v6 for the base network")
                invalidlist.append(reformattedprefixrange)
    print("number of valid entries: {}".format(len(tvallist)))
    print("number of invalid entries under '[Prefixes]': {}".format(len(invalidlist)))
    for badprefix in invalidlist:
        print(badprefix)
    return tvallist

"""
def validatePrefixList(pfList):
    '''
    validate the list of prefixes
    return list of valid and invalid prefixes
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
        except ValueError:
            invalidPFlist.append(item)
    valids = set(pfList) - set(invalidPFlist)
    return valids, invalidPFlist
"""

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
        components = re.split("[/-]", entry)
        if len(components) == 2:                                # no mask length option
            roareq += '{}|{}||'.format(components[0], components[1])
        else:                                                   # optional masklength
            roareq += '{}|{}|{}|'.format(components[0], components[1], components[2])
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
    try:
        subprocess.check_output(["openssl", "dgst", "-sha256", "-sign", privKey, "-keyform", "PEM", "-out",
                                 "signature", "roadata.txt"])
    except subprocess.CalledProcessError as e:
        print(e.output)
        os._exit(1)
    with open('sig_base64', 'w') as outfile:
        subprocess.call(["openssl", "enc", "-base64", "-in", "signature"], stdout=outfile)
    # combine the various pieces to make a complete signed request
    with open(filename, 'w') as final:
        final.write('-----BEGIN ROA REQUEST-----\n')
        with open('roadata.txt', 'r') as roadata:
            for line in roadata:
                final.write(line)
        final.write('\n')
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
    allInfo['Prefixes'] = preProcessPrefixes(allInfo['Prefixes'])
    roaRequstData = generateROAreqLine(allInfo)
    createSignedRequest(roaRequstData, allInfo['ROAName'], allInfo['Keyfile'])


main()
