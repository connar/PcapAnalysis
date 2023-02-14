### What is this script used for
This python script is useful when analyzing malware traffic pcaps. It's goal is to find all HTTP and HTTPS hosts that a victim IP interacted with. Once it runs through the pcap file and collects all hosts which interacted with the victim ip, it makes request to VirusTotal in order to distinguish the malicious ones with the rest. It saves the time that would take to manually search each one up but also helps the analyst in case he missed something.

### Requirements
To use this script, you need to create a profile in virus total. This is because you need an apikey provided by virus total in order for the script to successfully make requests to the endpoint.

### Usage
This script is run as :
```python3 associatedHosts.py [VictimIP] [virustotal_api_key] [pcapFile]```


### Example [from the BURNINCANDLE malware traffic exercise]
After this script is run upon the burnincandle exercise pcap file, it outputs the following : 
![image](https://user-images.githubusercontent.com/87579399/218774598-50ddcf72-17b0-4a45-b48f-fa19a6407231.png)


