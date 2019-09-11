## Simple Script to generate signed ROA Requests

A Python script to generate a signed ROA request that can be pasted into ARIN's RPKI portal.

This will be useful in cases where a large number of prefixes need to be included in one ROA.  It is inconvenient to use the web form to add these prefixes individually.

When using ARIN's Operational Test and Evaluation Environment (OT&E), you can use the "private" key of the [keypair publicly available](https://www.arin.net/resources/ote.html).

The script reads from ROAinfo.yml (by default, can be changed vi `-r` flag) the following information:
* Version (should always be 1, included for future compatibility if more versions are supported)
* ROA name
* Origin ASN
* Certificate start date (MM-DD-YYYY)
* Certificate expiration (MM-DD-YYYY)
* List of prefixes
* Name of the file containing the key to sign the request

The ROA request additionally requires a timestamp (the Unix Epoch) be in field #2.  This is automatically generated by the script.

The script uses Python `ipaddress` module to validate each prefix.  In the event of any error, the script exits.

IPv6 addresses are "normalized" to their compressed form, because (currently) ARIN's parser doesn't accept uncompressed addresses.  For example the first line results in an error,
<pre>2001:0db8:fff0::/44</pre>while theis entry would not:
<pre>2001:db8:fff0::/44</pre>

A file will be created based on the ROA name given in the YML file along with a timestamp.  For example, if you entered "MyFirstROA" as the ROA name, the output file will be `MyFirstROA_15AUG2018-1236.txt`.

### Use cases
When using hosted RPKI, ROAs can be requested via the ARIN portal.  Information can be entered into a web form, or, alternatively, a signed request can be used.
The signed request is useful if there are a large number of prefixes.  This script generates the text that gets posted into the portal.

