# Приклад реального звіту (Metasploitable2)

> **Провенанс:** справжній вивід конвеєра `scripts/run.py` проти навмисно вразливої
> Metasploitable2 (`192.168.56.101`) в ізольованій lab-мережі, модель `qwen2.5:3b`.
> Згенеровано на етапі **recon + vuln** (до інтеграції Hardening-агента в pipeline, M3.2),
> тому тут ще немає рядків **Mitigation/Detection** — у поточному конвеєрі вони додаються
> для пріоритезованих findings. Незмінений, крім цього заголовка.
>
> Ілюструє: реальні CVE з exploitdb (не вигадані моделлю), пріоритезацію (high-severity з
> CVE — вгорі), і чесне `_(no summary)_` там, де LLM-виклик впав у timeout на слабкому залізі.

---

# Recon Report — 2026-07-10_165831_recon-live

## Run metadata

- **Scenario:** recon-live
- **Targets:** 192.168.56.101
- **Operator:** woshe
- **Started:** 2026-07-10T16:58:31.110651+00:00

## Summary

| ID | Priority | Host | Port | Service | Product | Version | Severity |
|---|---|---|---|---|---|---|---|
| F-0019 | 1 | 192.168.56.101 | 5900 | vnc | VNC |  | high |
| F-0021 | 2 | 192.168.56.101 | 6667 | irc | UnrealIRCd |  | high |
| F-0001 | 3 | 192.168.56.101 | 21 | ftp | vsftpd | 2.3.4 | high |
| F-0003 | 4 | 192.168.56.101 | 23 | telnet | Linux telnetd |  | high |
| F-0002 | 5 | 192.168.56.101 | 22 | ssh | OpenSSH | 4.7p1 Debian 8ubuntu1 | info |
| F-0004 | 6 | 192.168.56.101 | 25 | smtp | Postfix smtpd |  | info |
| F-0005 | 7 | 192.168.56.101 | 53 | domain | ISC BIND | 9.4.2 | info |
| F-0006 | 8 | 192.168.56.101 | 80 | http | Apache httpd | 2.2.8 | info |
| F-0007 | 9 | 192.168.56.101 | 111 | rpcbind |  | 2 | info |
| F-0008 | 10 | 192.168.56.101 | 139 | netbios-ssn | Samba smbd | 3.X - 4.X | info |
| F-0009 | 11 | 192.168.56.101 | 445 | netbios-ssn | Samba smbd | 3.X - 4.X | info |
| F-0010 | 12 | 192.168.56.101 | 512 | exec | netkit-rsh rexecd |  | info |
| F-0011 | 13 | 192.168.56.101 | 513 | login |  |  | info |
| F-0012 | 14 | 192.168.56.101 | 514 | shell | Netkit rshd |  | info |
| F-0013 | 15 | 192.168.56.101 | 1099 | java-rmi | GNU Classpath grmiregistry |  | info |
| F-0014 | 16 | 192.168.56.101 | 1524 | bindshell | Metasploitable root shell |  | info |
| F-0015 | 17 | 192.168.56.101 | 2049 | nfs |  | 2-4 | info |
| F-0016 | 18 | 192.168.56.101 | 2121 | ftp | ProFTPD | 1.3.1 | info |
| F-0017 | 19 | 192.168.56.101 | 3306 | mysql | MySQL | 5.0.51a-3ubuntu5 | info |
| F-0018 | 20 | 192.168.56.101 | 5432 | postgresql | PostgreSQL DB | 8.3.0 - 8.3.7 | info |
| F-0020 | 21 | 192.168.56.101 | 6000 | X11 |  |  | info |
| F-0022 | 22 | 192.168.56.101 | 8009 | ajp13 | Apache Jserv |  | info |
| F-0023 | 23 | 192.168.56.101 | 8180 | http | Apache Tomcat/Coyote JSP engine | 1.1 | info |

## Findings

### F-0019 — 192.168.56.101:5900/tcp vnc

**Summary:** The observed VNC service on port 5900/tcp running on host 192.168.56.101 has a relatively simple attack surface as it is primarily used for remote desktop access. The lack of version information suggests that the configuration might be default or not updated, which could expose the system to known vulnerabilities related to insecure VNC configurations such as weak authentication methods and default credentials. 

**Next steps:**
- Check if the service is running with a default username and password.
- Verify if the service uses secure protocols like TLS/SSL for data encryption.
- Review the firewall settings to ensure that only trusted networks can access the VNC server.

**CVEs:** CVE-2007-3536, CVE-2007-0756, CVE-2008-2382, CVE-2001-0167, CVE-2006-2369, CVE-2008-3493, CVE-2007-2526, CVE-2002-0994, CVE-2019-17662, CVE-2024-42049, CVE-2009-0388, CVE-2006-1652, CVE-2008-0610, CVE-2013-5745, CVE-2001-0168

### F-0021 — 192.168.56.101:6667/tcp irc

**Summary:** The observed service is UnrealIRCd running on port 6667 of the host 192.168.56.101. This IRC server could be a potential entry point for attackers to compromise the system, especially if it's not properly configured or updated with the latest security patches. The lack of version information makes it difficult to assess its exact vulnerabilities and attack surface.

**Next steps:**
- Check for known vulnerabilities in UnrealIRCd by comparing against the latest CVE database.
- Verify that the server is running the most recent version, as newer versions often include critical security fixes.
- Review the configuration of the IRC server to ensure it does not expose unnecessary features or settings that could be exploited.

**CVEs:** CVE-2010-2075, CVE-2006-1214

### F-0001 — 192.168.56.101:21/tcp ftp

**Summary:** _(no summary)_

**CVEs:** CVE-2011-2523

### F-0003 — 192.168.56.101:23/tcp telnet

**Summary:** The observed telnet service on port 23/tcp is running the Linux telnetd version without a specific version number. This indicates that the system might be using an outdated version of the telnet server software, which could expose it to known vulnerabilities and weaknesses in older versions. The lack of a version number also suggests that this service may not have been updated for years or has never been configured with a proper version number. Attackers could potentially exploit these known vulnerabilities by sending specially crafted data packets designed to take advantage of the specific flaws present in older telnetd implementations.

**CVEs:** CVE-2011-4862

### F-0002 — 192.168.56.101:22/tcp ssh

**Summary:** The observed service is OpenSSH version 4.7p1, which is an outdated version and potentially vulnerable to various security issues such as vulnerabilities in older cryptographic algorithms or authentication methods. The attack surface includes potential unauthorized access due to weak encryption, outdated security protocols, and possible misconfigurations that could allow for brute force attacks or man-in-the-middle (MITM) attacks.

### F-0004 — 192.168.56.101:25/tcp smtp

**Summary:** The observed service is Postfix smtpd on port 25/tcp at the host 192.168.56.101. This service is commonly used for sending email via SMTP protocol. Given that it's a well-known and widely deployed mail transfer agent, it represents a significant attack surface due to its role in facilitating both legitimate and malicious communications. The lack of version information makes it difficult to assess specific vulnerabilities or weaknesses related to this particular instance. 

### F-0005 — 192.168.56.101:53/tcp domain

**Summary:** _(no summary)_

### F-0006 — 192.168.56.101:80/tcp http

**Summary:** The observed Apache HTTP server running on port 80/tcp is vulnerable to several security risks due to its outdated version (2.2.8), which may expose it to known vulnerabilities such as buffer overflows, remote code execution, or directory traversal attacks. Additionally, the lack of proper configuration settings could further compromise the service's security posture.

**Next steps:**
- Check for and apply any available security patches or updates to upgrade Apache httpd to a more recent version.
- Review server configurations (e.g., .htaccess files, DirectoryIndex directive) to ensure they do not expose sensitive information or allow unauthorized access.
- Implement proper authentication mechanisms such as Basic Auth or mod_auth_mellon for securing the HTTP service.

### F-0007 — 192.168.56.101:111/tcp rpcbind

**Summary:** The rpcbind service is running on port 111/tcp on the host 192.168.56.101 with a version of 2. This service is used for dynamic registration of services in Unix systems, and it can be exploited if misconfigured or outdated. It's important to ensure that rpcbind is only accessible from trusted hosts and configured correctly.

**Next steps:**
- Check the firewall rules to see if rpcbind is allowed to communicate externally.
- Verify that rpcbind is not set up to listen on all interfaces (0.0.0.0). It should be restricted to specific IP addresses or a range of IPs.
- Review the system's configuration files for rpcbind, such as /etc/rpc and /etc/exports, to ensure they are secure.

### F-0008 — 192.168.56.101:139/tcp netbios-ssn

**Summary:** _(no summary)_

### F-0009 — 192.168.56.101:445/tcp netbios-ssn

**Summary:** The observed service on port 445/tcp is Samba SMB (SMBd) running in versions 3.X to 4.X, which is commonly used for file sharing and remote procedure calls. The attack surface includes potential vulnerabilities such as SMBv1 protocol deprecation, SMB2 Protocol vulnerabilities, and misconfigurations that could allow unauthorized access or data exfiltration. Next analysis steps should focus on checking if the SMB server supports SMBv1 (which is deprecated), comparing with a known secure version to identify any discrepancies in configuration settings, and reviewing firewall rules for port 445/tcp.

**Next steps:**
- Check if the Samba service supports SMBv1 protocol by running tests or commands like smbclient against the host.
- Compare the observed versions (3.X - 4.X) with a known secure version to identify any misconfigurations that could expose the system, such as disabling security features or enabling insecure protocols.
- Review firewall rules and Samba configuration files for port 445/tcp to ensure only authorized hosts can connect.

### F-0010 — 192.168.56.101:512/tcp exec

**Summary:** The observed service on port 512/tcp is the netkit-rsh rexecd from the exec family. This service is part of a legacy shell remote execution system that has been superseded by more secure alternatives like OpenSSH. Given its age and lack of version information, it may be vulnerable to known vulnerabilities or misconfigurations.

**Next steps:**
- Check for configuration settings that could expose this service to unauthorized access, such as allowing root login without a password.
- Review the system's installed packages and compare them with those expected in a secure environment. Look for any outdated versions of netkit-rsh or other related services.
- Examine the firewall rules to ensure they are configured correctly and do not allow this service to be accessed from untrusted networks.

### F-0011 — 192.168.56.101:513/tcp login

**Summary:** The observed service on port 513/tcp is a login service with no specific product or version information provided. This service could be related to an unprivileged remote login protocol such as rlogin (now deprecated), or it might be part of a custom application. Given the lack of details, there are potential vulnerabilities associated with its implementation and configuration that need further investigation.

### F-0012 — 192.168.56.101:514/tcp shell

**Summary:** The observed service is Netkit rshd on port 514/tcp running on host 192.168.56.101. This service is an older version of the Remote Shell Daemon (rshd) from the NetKit package, which has been deprecated and removed in more recent versions of Unix-like operating systems. The lack of a specific version number suggests it might be outdated or improperly configured. Given its age and known vulnerabilities, this service could pose a risk if misconfigured or exposed to unauthorized users.

**Next steps:**
- Check for any configuration files (e.g., /etc/ssh/sshd_config) that might still reference Netkit rshd.
- Verify the firewall rules to ensure it is not open to external traffic, which would expose this service to potential attacks.
- Review system logs and access control mechanisms to identify if there are any signs of unauthorized use or misconfiguration.

### F-0013 — 192.168.56.101:1099/tcp java-rmi

**Summary:** The observed service is a Java Remote Method Invocation (RMI) registry running on GNU Classpath version 0.89, which is an older and less secure implementation of the RMI protocol compared to standard Java implementations. The attack surface includes potential vulnerabilities related to insecure configuration settings or known weaknesses in this specific version of GNU Classpath. 

**Next steps:**
- Check for misconfigurations such as exposing the service on a public network, using default ports, or allowing access from all networks.
- Verify if there are any known exploits targeting this specific combination of product and version (GNU Classpath 0.89 with java-rmi).
- Review the configuration files associated with the RMI registry to ensure they do not contain sensitive information or allow unauthorized access.

### F-0014 — 192.168.56.101:1524/tcp bindshell

**Summary:** The observed service is an active Metasploitable root shell running on port 1524/tcp on the host 192.168.56.101. This service represents a significant attack surface due to its ability to provide remote access and execute commands as root, which could be used for further exploitation or command injection attacks. The lack of version information suggests that this might be an older configuration or potentially misconfigured.

### F-0015 — 192.168.56.101:2049/tcp nfs

**Summary:** The observed NFS service on port 2049/tcp is running version 2-4 on the host 192.168.56.101. The attack surface includes potential vulnerabilities related to outdated versions of NFS, which could be exploited by attackers with specific permissions or if misconfigured. Attackers might attempt to exploit known weaknesses in older versions of NFS that allow unauthorized access or denial-of-service conditions.

**Next steps:**
- Check for any configuration files (e.g., /etc/exports) that may expose the service to unnecessary network traffic, which could be exploited by attackers.
- Verify if there are any known vulnerabilities associated with version 2-4 of NFS. This can help determine if immediate remediation is necessary or if monitoring should suffice until a patch becomes available.
- Review access control lists (ACLs) and security policies to ensure that the service is not exposed to unauthorized hosts or networks.

### F-0016 — 192.168.56.101:2121/tcp ftp

**Summary:** The ProFTPD service on port 2121/tcp is running version 1.3.1, which is an older version of the software. Older versions may be vulnerable to known security vulnerabilities that have been patched in more recent releases.

**Next steps:**
- Check if there are any known vulnerabilities specific to this version of ProFTPD by comparing with a list of known vulnerabilities for FTP servers.
- Review the configuration file (usually named 'proftpd.conf') for any insecure settings or commands that could be exploited, such as anonymous login enabled without password protection.
- Verify if the service is using default credentials like an empty username and password combination, which can be used to gain unauthorized access.

### F-0017 — 192.168.56.101:3306/tcp mysql

**Summary:** The observed MySQL service on port 3306 is running an outdated version (5.0.51a-3ubuntu5) which exposes the system to known security vulnerabilities that have been patched in more recent versions of MySQL. This includes potential SQL injection attacks, weak authentication mechanisms, and other issues related to older protocol implementations.

**Next steps:**
- Check for additional services running on the host that might be using this database server.
- Verify if there are any misconfigurations such as open_basedir restrictions or default root login enabled which could further reduce security risks.
- Compare the version with a more secure MySQL version (e.g., 5.7.x) to identify and address specific vulnerabilities.

### F-0018 — 192.168.56.101:5432/tcp postgresql

**Summary:** The observed PostgreSQL service on port 5432 is running an older version (8.3.0 - 8.3.7) of the database management system. This version is known to be vulnerable to several security issues, including outdated encryption methods and potential SQL injection vulnerabilities. The attack surface includes unauthorized access through this specific PostgreSQL instance, as well as any data stored or processed by it.

**Next steps:**
- Compare the observed version with the latest available versions of PostgreSQL to identify if there are any known security patches that have been released since 8.3.0.
- Review the database configuration settings for any misconfigurations such as default passwords, insecure authentication methods, or open administrative ports which could be exploited by attackers.
- Perform a thorough vulnerability assessment on this specific instance using tools like Nmap with scripts tailored to PostgreSQL, and check for known vulnerabilities that might not have been patched in the observed version.

### F-0020 — 192.168.56.101:6000/tcp X11

**Summary:** The observed service on port 6000/tcp is X11, which is a display server protocol used by Unix-like operating systems to render graphical user interfaces. Since the product and version are unknown, it's unclear if this service is running a standard or potentially vulnerable version of X11. The attack surface includes potential vulnerabilities in the X11 protocol implementation that could be exploited for remote code execution, buffer overflows, or other security issues. 

**Next steps:**
- Check for known vulnerabilities in the X11 protocol by reviewing CVEs and advisories.
- Compare this service with standard configurations to identify any deviations that might indicate misconfigurations or potential exploitation vectors.
- Review the system's configuration files related to X11, such as xorg.conf or Xsession, to ensure they are secure and do not expose default settings.

### F-0022 — 192.168.56.101:8009/tcp ajp13

**Summary:** The observed service is Apache Jserv running on port 8009 of the host 192.168.56.101. This service is part of the Apache Tomcat web server suite. The lack of version information indicates that a specific version might be vulnerable to known weaknesses or misconfigurations, such as outdated libraries or default configurations. Attackers could exploit these vulnerabilities for remote code execution, denial-of-service attacks, or other types of attacks.

**Next steps:**
- Check the Apache Tomcat configuration files (e.g., server.xml and web.xml) for any misconfigurations that might expose this service to unauthorized access.
- Verify if there are known vulnerabilities associated with the version range of Apache Jserv by checking the official Apache security advisories or vulnerability databases like CVEs.
- Review the installed libraries and dependencies within Tomcat, as older versions may contain known vulnerabilities. Ensure all components are up-to-date.

### F-0023 — 192.168.56.101:8180/tcp http

**Summary:** The observed service is an Apache Tomcat/Coyote JSP engine running on port 8180 of the host 192.168.56.101. This version (1.1) of Tomcat is relatively old and may be vulnerable to known security vulnerabilities, such as those related to outdated servlet container versions or misconfigured web applications. Additionally, if this service is accessible via a non-standard port like 8180, it might indicate that the system administrator has not properly secured the server by disabling unnecessary services.
