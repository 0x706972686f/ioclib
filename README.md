# ioclib

In the security space we often have a single indicator of compromise (IOC), that we need to query against multiple API endpoints to build up context around it. Simple examples include a SHA256 hash being looked up in VirusTotal, or the DNS entry for an IPv4 address.

`ioclib` is an open solution to this. It's a type-driven, parrelised python library for aggregating multiple API endpoints together. It uses `aynscio` to simultaneously connect to multiple API endpoints to retrieve information, and then return the information in JSON format for simple ingestion and understanding.

Some of the current integrations include:
- Shodan
- VirusTotal
- GreyNoise
- AlientVault OTX
- Intel X
- Google Safe Browsing
- Malware Bazaar
- ScreenShot API
- URL Scan
- Triage

## Secrets
Some API endpoints require authorisation to access them, to add a key you can edit the secrets.py file to point to an Environment variable:

```
SECRET_KEY = os.environ['secret']
```

## Using
Here's an example using the `sha256ioc.py` library, but the same process is relevant for the others as well. 
```
from sha256ioc import sha256ioc

sha256_ioc_obj = sha256ioc('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
sha256_result_json = sha256_ioc_obj.get_result()
```

## Customisation
There's two types of customisation, adding an IOC type, or adding an API endpoint

### API Endpoint
If you wish to add an API endpoint that is not present, it's a simple matter of modifying the IOC type python file, creating a function based off the template, then modifying the `gather_urls` function, appending it to the `exec_methods` array.

Below is an example for VirusTotal. The source dict comprises of the name of the API endpoint, the HTTP status type, if the API endpoint needs HTTP data for the request it can be added to the data field, and if it requires a HTTP header that can also be added, finally the url.

```
    async def query_vt(self) -> dict:
        """query_vt
        Returns a dictionary for querying the VirusTotal API.

        Refer to documentation for details: https://developers.virustotal.com/reference/ip-info

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "VirusTotal"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {
            "x-apikey": f"{secrets.VIRUSTOTAL_API_KEY}",
            "Accept": "application/json",
        }
        source_dict["url"] = f"https://www.virustotal.com/api/v3/files/{self.sha256}"
        return source_dict
```

Each ioc library type (i.e: `sha256ioc.py`) then has a `gather_urls` function, which contains an array of all of the functions to call. Amending your nearly created function will execute it. This also means if you don't want it to hit a specific API endpoint you can remove it from the list.

```
exec_methods = [
    "query_malwarebazaar",
    "query_vt",
    "query_alientvaultotx",
    "query_threatminer_avdetections",
    "query_threatminer_metadata",
]
```     

### New IOC Type
Potentially you want to add an additional IOC type, for instance, you want to handle an `IPv6` address, or `MD5` hash instead. You can simply use the `sha256ioc.py`, `ipv4ioc.py` and `urlioc.py` as an example for modification.

It firstly needs to inherent from the `ioc.py` base file, which contains the asyncio library that actually calls the endpoints. The `get_result` function calls the parent `ioc.py` library and returns the information. The `gather_urls` function calls all of the functions for the individual endpoints and feeds that into the parent library for execution.

Then for each API endpoint a relevant function is created that meets the template.
   
## Asynchronous Calls
The base `ioc.py` file does the brunt of the work, it calls all of the functions asynchronously to grab the details for each API endpoint (including URL, headers and more). It then uses an asycio producer to populate and prepare a httpx asyncio client, populates it in a asyncio queue and then executes them all simultaneously.

This means that the longest the response can be is the slowest API endpoint you're talking to.
