## Simple Script to generate signed ROA Requests

An interactive Python script to generate a signed ROA request that can be pasted into ARIN's RPKI portal.

This will be useful in cases where a large number of prefixes need to be included in one ROA.  It is inconvenient to use the web form to add these prefixes.

When testing in ARIN's Operational Test and Evaluation Environment (OT&E), you can use the "private" key of the [keypair publicly available](https://www.arin.net/resources/ote.html).

The interactive script will ask for the following information:
* ASN
* ROA name
* File containing prefixes (defaults to `prefix`)
* Certificate start date (default is today's date)
* Certificate expiration
* Name of the file containing the key to sign the request (defauls to `orgkey.pem`)

The file of prefixes should contain a single prefix (v4 or v6) per line.  Comments are noted by `#`

The script uses Pythong `ipaddress` module to validate each prefix.  In the event of any error, the script exits.

IPv6 addresses are "normalized" to their compressed form, because (currently) ARON's parser doesn't accept uncompressed addresses.  For example,
<pre>2001:0db8:fff0::/44</pre> would result in an error, while
<pre>2001:db8:fff0::/44</pre> would not.

The script creates a file called `SignedRequest.`  This can then be pasted into ARIN's Hosted RPKI Portal.

### Use cases
The current guidance on creating RPKI ROAs is *not* use the optional Max Length field to allow a range of prefixes.
This might be useful if you needed to have all 256 /24s in the /16 have a covering ROA for something like cloud-based DDoS mitigation, where a different AS originates the prefix,

For example,  if you had 172.16.0.0/16 and needed to have some (or all) of the /24 subnets be validated, you could create a ROA that covered 172.16.0.0/16-24.
This means that all mask lengths between 16-24 are valid.

The problem with this is that an attacker could advertise a /17 (also spoofing the authorized ASN), resulting in a cryptographicallyvalid, but illegitimate advertisement.

The alternative is to create a ROA (or multiple ROAs) that explicitly list the specific prefixes.  In this example, there would be an entry for the summary /16 and 256 /24s.

This script makes this easy by processing a list of prefixes, generating the ROA request line, signing the request, and formatting the data into a format suitable for entry into the Hosted RPKI Portal.

#### Generating lots of prefixes
Any method can be used, include export from an IPAM system.  Below are two one-liners that can be used to generate lots of prefixes.

[SIPCALC](https://github.com/sii/sipcalc) can be used to generate and split v4 and v6 prefixes.  The assumption in these examples is that you want to evenly split a summary prefix into equal sized subnets.

To split a an IPv6 /44 into 16 /48s, use:
<pre>sipcalc 2001:0db8:fff0::/44 --v6split=48| grep Network | awk '{print $3"/48" }'
2001:0db8:fff0:0000:0000:0000:0000:0000/48
2001:0db8:fff1:0000:0000:0000:0000:0000/48
2001:0db8:fff2:0000:0000:0000:0000:0000/48
                <snip>
2001:0db8:fffe:0000:0000:0000:0000:0000/48
2001:0db8:ffff:0000:0000:0000:0000:0000/48</pre>

(note, this list doesn't contain the summary /44

An IPv4 example:
<pre>
sipcalc 172.16.0.0/16 --v4split=18 | grep Network | awk '{print $3"/18" }'
172.16.0.0/18
172.16.64.0/18
172.16.128.0/18
172.16.192.0/18
</pre>
(again, the summary /16 would need to be added to the file)
