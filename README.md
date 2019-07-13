# Reputation-Identifier
Identifies the Threat Score for Domains, Urls, Hashes and FileScan <br/>
Its a Tool which communicates to VirusTotal through API, It Performs Several Functionalities <br/>
<b>Domain Check</b>: Checks the Reputation of Domain either single or multiples<br/>
<b>Url Check</b>: Checks the Repuatation of Url either single or multiples<br/>
<b>Hash Check</b>: Checks the Hash Reputations either single or multiples<br/>
<b>FileScan</b>: Scan the File provided by the user by the giving the response as malicious or not, it scans single or multiple files<br/>
  
  ### Required Python Packages
  The below listed packages are required to run the script in python<br/>
  <b>1. requests</b><br/>
  <b>2. pandas</b>
  
  ### Limitations
  Virus Total Public API provides 4 api calls per minute, so please provide the only 4 threat data to it in a single time
  
  ### Output
  For a single Threat response, output will be shown in console itself<br/>
  For Multiple Threat responses, output will be shown in console and based on user intention output can be stored in a csv file
