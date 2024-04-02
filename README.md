# THM: Benign

In this SOC oriented CTF we will investigate compromised host using Splunk.

[https://tryhackme.com/r/room/benign](https://tryhackme.com/r/room/benign)

# Scenario:

One of the client’s IDS indicated a potentially suspicious process execution indicating one of the hosts from the HR department was compromised. Some tools related to network information gathering / scheduled tasks were executed which confirmed the suspicion. Due to limited resources, we could only pull the process execution logs with Event ID: 4688 and ingested them into Splunk with the index **win_eventlogs** for further investigation.  The network is divided into three logical segments. It will help in the investigation:

**IT Department**

- James
- Moin
- Katrina

**HR department**

- Haroon
- Chris
- Diana

**Marketing department**

- Bell
- Amelia
- Deepak

### How many logs are ingested from the month of March, 2022?

Lets prepare our search in Splunk Search Head by narrowing the index with **win_eventlogs** as the Scenario suggested and narrow the search by using **Date Range** next to **Search Head**.

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled.png)

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled%201.png)

**Answer:** 13959

### Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?

Okay we have 9 legit usernames provided in Scenario - lets build an query to exclude all the legit usernames from the logs and check the leftovers if there is anything strange.

**index="win_eventlogs" UserName!="James" AND UserName!="Moin" AND UserName!="Katrina" AND UserName!="Haroon" AND UserName!="Chris" AND UserName!="Diana" AND UserName!="Bell" AND UserName!="Amelia" AND UserName!="Deepak”**

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled%202.png)

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled%203.png)

**Answer**: Amel1a

### Which user from the HR department was observed to be running scheduled tasks?

In order to schedule task in the Windows command line we need to use **schtasks** utility. Lets see the documentation and check for syntax [here](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks) and lets observe syntax section:

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled%204.png)

Okay, clearly command **/create** gives us ability to create task, lets use this in our query.

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled%205.png)

Query will points us to the single event with username.

**Answer:**  Chris.fort 

### Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host.

Okay, lets narrow our search from the start by specifying HR staff only - Haroon, Chris and Diana and search for commands executed by these users. 

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled%206.png)

Once we narrowed the search lets examine the results:

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled%207.png)

**LOLBins** is the abbreviated term for Living Off the Land Binaries. Living Off the Land Binaries are binaries of a non-malicious nature, local to the operating system, that have been utilized and exploited by cyber criminals and crime groups to camouflage their malicious activity.

We can see that someone used **certutil.exe** which is popular Windows command-line utility that can be used for handling certificates in Windows but also has the capability to download files from the internet with its -**urlcache** flag. This method is often used by attackers because it's less suspicious, but it can be used for legitimate purposes as well. Once we open the details, we will find our more details and also our culprit.

**Answer:** haroon

### **To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?**

As we mentioned in previous question, **LOLBIN’s** are system binaries. Looking through the details, the answer is clear.

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled%208.png)

**Answer:** certutil.exe

### What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)

Looking through the details, there is **EventTime** field which will provide the answer.

**Answer:** 2022-03-04

### Which third-party site was accessed to download the malicious payload?

Looking through the details, the answer is clear.

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled%208.png)

**Answer:** [controlc.com](http://controlc.com/)

### What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?

Looking through the details, the answer is clear.

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled%208.png)

**Answer:** benign.exe

### The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?

We will use curl utility and narrow the search by provided pattern.

![Untitled](THM%20Benign%20bec24d756dda4b84887cc289d9eb31e5/Untitled%209.png)

**Answer:** THM{KJ&*H^B0}

### What is the URL that the infected host connected to?

**Answer:** [https://controlc.com/e4d11035](https://controlc.com/e4d11035)

Annnd done, thanks for stopping by.