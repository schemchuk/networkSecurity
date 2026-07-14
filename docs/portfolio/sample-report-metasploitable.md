# Приклад реального звіту (Metasploitable2) — повний конвеєр

> **Провенанс:** справжній, незмінений вивід `scripts/run.py` (крім цього заголовка)
> проти навмисно вразливої Metasploitable2 (`192.168.56.101`) в ізольованій host-only
> lab-мережі. Модель `qwen2.5:3b` через локальний Ollama, повний конвеєр
> **Recon → Vuln Analysis → Hardening**.
>
> **Що ілюструє:**
> - реальні CVE з локального exploitdb (`searchsploit`) — модель їх не вигадує;
> - пріоритезацію: high-severity findings з CVE підняті вгору Summary;
> - blue-team поради **Mitigation/Detection** для пріоритезованих findings.
>
> **Чесно про залізо:** з 22 портів 3 recon-резюме порожні (`_(no summary)_`) — LLM-виклики
> перевищили timeout на слабкому залізі (той самий constraint, що описують
> [benchmarks](../benchmarks/model-selection-recon.md) і
> [hardware-upgrade-rationale](../hardware-upgrade-rationale.md)). Hardening-поради
> згенеровано для всіх 4 пріоритезованих findings.

---

# Recon Report — 2026-07-14_103839_recon-full-m3

## Run metadata

- **Scenario:** recon-full-m3
- **Targets:** 192.168.56.101
- **Operator:** woshe
- **Started:** 2026-07-14T10:38:39.741424+00:00

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
| F-0011 | 13 | 192.168.56.101 | 513 | login | OpenBSD or Solaris rlogind |  | info |
| F-0012 | 14 | 192.168.56.101 | 514 | shell | Netkit rshd |  | info |
| F-0013 | 15 | 192.168.56.101 | 1099 | java-rmi | GNU Classpath grmiregistry |  | info |
| F-0014 | 16 | 192.168.56.101 | 1524 | bindshell | Metasploitable root shell |  | info |
| F-0015 | 17 | 192.168.56.101 | 2049 | nfs |  | 2-4 | info |
| F-0016 | 18 | 192.168.56.101 | 2121 | ftp | ProFTPD | 1.3.1 | info |
| F-0017 | 19 | 192.168.56.101 | 3306 | mysql | MySQL | 5.0.51a-3ubuntu5 | info |
| F-0018 | 20 | 192.168.56.101 | 5432 | postgresql | PostgreSQL DB | 8.3.0 - 8.3.7 | info |
| F-0020 | 21 | 192.168.56.101 | 6000 | X11 |  |  | info |
| F-0022 | 22 | 192.168.56.101 | 8180 |  |  |  | info |

## Findings

### F-0019 — 192.168.56.101:5900/tcp vnc

**Summary:** The observed VNC service on port 5900/tcp running on host 192.168.56.101 is vulnerable to a wide range of attacks due to its unencrypted nature and the lack of version information, which could indicate outdated software. The attack surface includes potential man-in-the-middle attacks, password sniffing, and session hijacking if not properly secured.

**Next steps:**
- Check for known vulnerabilities in VNC versions that are less than 6.0 by comparing with a list of common VNC server versions.
- Verify the configuration settings to ensure security features such as authentication, encryption (if used), and access control lists are enabled.
- Review any logs or audit trails on the host to detect unauthorized connections or unusual activity related to this service.

**CVEs:** CVE-2007-3536, CVE-2007-0756, CVE-2008-2382, CVE-2001-0167, CVE-2006-2369, CVE-2008-3493, CVE-2007-2526, CVE-2002-0994, CVE-2019-17662, CVE-2024-42049, CVE-2009-0388, CVE-2006-1652, CVE-2008-0610, CVE-2013-5745, CVE-2001-0168

**Mitigation:** Implement strong authentication methods such as two-factor authentication (2FA) for all VNC sessions to enhance security.

**Detection:** Monitor system logs and application logs for failed login attempts, unauthorized access events, and suspicious activity related to the VNC service on host 192.168.56.101:5900.

### F-0021 — 192.168.56.101:6667/tcp irc

**Summary:** The observed service is UnrealIRCd running on port 6667 of host 192.168.56.101. This IRC server could be a potential entry point for attackers to exploit vulnerabilities in the software, especially if it's not properly configured or updated. The lack of version information makes it difficult to assess specific known vulnerabilities.

**Next steps:**
- Check for updates and ensure that UnrealIRCd is running the latest version.
- Verify that the IRC server has secure configuration settings such as using a strong password and limiting access through authentication mechanisms.
- Review any existing configurations or logs for signs of unauthorized activity or unusual traffic patterns.

**CVEs:** CVE-2010-2075, CVE-2006-1214

**Mitigation:** type: hardening; input_value: ['Disable IRC services that are not in use to reduce attack surface.', 'Update UnrealIRCd to the latest version to benefit from security patches.', 'Configure UnrealIRCd with secure settings, such as disabling anonymous login and enabling SSL/TLS encryption.']; input_type: list

**Detection:** type: log_monitoring; input_value: ['Monitor logs for unauthorized access attempts to the IRC server.', 'Look for unusual traffic patterns or connections from unknown sources.', 'Check for failed login attempts and suspicious user activity.']; input_type: list

### F-0001 — 192.168.56.101:21/tcp ftp

**Summary:** The observed FTP service on port 21/tcp is running vsftpd version 2.3.4 on the host 192.168.56.101. The latest version of vsftpd as of now is 3.0.7, indicating that there might be security updates available to mitigate potential vulnerabilities. The attack surface includes unauthorized access and possibly insecure configurations such as anonymous FTP enabled or root login allowed without password.

**CVEs:** CVE-2011-2523

**Mitigation:** Disable the FTP service on the server at 192.168.56.101.

**Detection:** Logs of failed login attempts and unauthorized access attempts, as well as system logs indicating changes to the vsftpd configuration file.

### F-0003 — 192.168.56.101:23/tcp telnet

**Summary:** The observed telnet service on port 23/tcp is running the Linux telnetd version without a specific version number. This indicates that it might be using an outdated version of the software, which could expose the system to known vulnerabilities such as buffer overflow attacks or authentication bypass issues. The lack of a precise version makes it difficult to determine if any patches have been applied to address these risks.

**CVEs:** CVE-2011-4862

**Mitigation:** Disable the Telnet service to eliminate the risk of unauthorized access.

**Detection:** Monitor system logs for suspicious activities related to Telnet, such as failed login attempts and unauthorized connections.

### F-0002 — 192.168.56.101:22/tcp ssh

**Summary:** The observed service is OpenSSH version 4.7p1 from Debian 8ubuntu1 running on the host 192.168.56.101 on port 22/tcp. This version of OpenSSH is quite outdated, which exposes the system to a significant attack surface including known vulnerabilities that have been patched in more recent versions. The configuration and security settings should also be reviewed for any potential misconfigurations or weaknesses.

**Next steps:**
- Check if there are any known vulnerabilities affecting this specific version of OpenSSH by consulting advisories from trusted sources.
- Review the SSH server configuration file (sshd_config) to ensure that it is secure, with appropriate settings such as disabling root login via password and enabling public key authentication.
- Verify that all services running on the host are up-to-date. In particular, check for any other outdated software or dependencies that could be exploited.

### F-0004 — 192.168.56.101:25/tcp smtp

**Summary:** The observed service is Postfix smtpd running on port 25/tcp at the host 192.168.56.101. This service is a common SMTP server used for email transmission. Given that it's not versioned, there may be default configurations or vulnerabilities associated with its installation and configuration. The attack surface includes potential misconfigurations such as open relay issues, insecure authentication methods, or outdated security patches.

### F-0005 — 192.168.56.101:53/tcp domain

**Summary:** _(no summary)_

### F-0006 — 192.168.56.101:80/tcp http

**Summary:** The observed service is an older version of Apache HTTP Server (2.2.8) running on port 80/tcp at the host 192.168.56.101. This configuration represents a significant attack surface due to its age, which may expose vulnerabilities related to known weaknesses and outdated security patches. The primary risk is potential exploitation of known vulnerabilities such as Apache Struts vulnerabilities (e.g., CVE-2017-5638) or other older versions' inherent risks.

### F-0007 — 192.168.56.101:111/tcp rpcbind

**Summary:** The rpcbind service is running on port 111/tcp on the host 192.168.56.101 with a version of 2. This service is used for dynamic registration of services, and its presence indicates that other network services might be registered through it. The low version number (2) suggests potential vulnerabilities or outdated configurations which could be exploited by attackers.

### F-0008 — 192.168.56.101:139/tcp netbios-ssn

**Summary:** _(no summary)_

### F-0009 — 192.168.56.101:445/tcp netbios-ssn

**Summary:** _(no summary)_

### F-0010 — 192.168.56.101:512/tcp exec

**Summary:** The observed service is an outdated version of the netkit-rsh rexecd daemon running on port 512/tcp. This service is deprecated and has been superseded by modern SSH (Secure Shell) protocols. The lack of a specific version number suggests it might be installed as part of an older system or configuration, which could indicate potential misconfigurations or vulnerabilities related to its use in place of more secure alternatives like SSH. 

**Next steps:**
- Check for other deprecated services on the host that may also need attention.
- Review the system's version history and configurations to identify if there are any known vulnerabilities associated with this service, especially those not covered by newer protocols.
- Verify if there are any misconfigurations or outdated dependencies that could expose the service to potential attacks.

### F-0011 — 192.168.56.101:513/tcp login

**Summary:** The observed service on port 513/tcp is the login daemon of either OpenBSD or Solaris systems. This service is primarily used for remote system logging in these environments. Given that it's a legacy service with potential security implications, understanding its configuration and any known vulnerabilities would be prudent steps to mitigate risks.

### F-0012 — 192.168.56.101:514/tcp shell

**Summary:** The observed service is Netkit rshd on port 514/tcp running on host 192.168.56.101. This service is part of the older Netkit Unix suite, which was superseded by OpenSSH in most environments. The lack of a version number suggests it might be outdated or improperly configured. Given its age and potential for misconfiguration, it could expose the system to remote command execution vulnerabilities if not properly secured.

**Next steps:**
- Check for known security advisories related to Netkit rshd versions that are older than OpenSSH.
- Verify if this service is used in a configuration that allows password-based authentication, which can be exploited by attackers.
- Review the system's SSH configuration (if applicable) to ensure it does not rely on deprecated services like Netkit rshd.

### F-0013 — 192.168.56.101:1099/tcp java-rmi

**Summary:** The observed service is an RMI server running GNU Classpath on port 1099. This setup could potentially expose the system to remote code execution vulnerabilities if the version of GNU Classpath is outdated or misconfigured. The attack surface includes potential security risks associated with this specific implementation and configuration.

### F-0014 — 192.168.56.101:1524/tcp bindshell

**Summary:** The service observed is a bindshell on port 1524/tcp running Metasploitable root shell. This indicates an unauthorized remote execution capability that could be used to establish a backdoor connection with the attacker's server. The lack of version information suggests it might be a custom or outdated implementation, which can expose vulnerabilities not covered by standard versions. The attack surface includes potential for unauthorized command execution and data exfiltration from the compromised host.

### F-0015 — 192.168.56.101:2049/tcp nfs

**Summary:** The service on port 2049/tcp is the NFSv2/v3 protocol running on a version that is considered outdated (2-4). This older version of NFS may be vulnerable to various security issues such as buffer overflows, authentication vulnerabilities, and other known weaknesses. The attack surface includes potential unauthorized access or data leakage if not properly configured.

**Next steps:**
- Check the configuration settings for any misconfigurations that could expose the service, such as allowing insecure protocols (e.g., NFSv2) on a network interface.
- Review the system logs and audit trails to identify any unusual activity related to this service. Look for signs of unauthorized access or data exfiltration attempts.
- Compare the version with more secure versions of NFS (such as NFSv4) to determine if upgrading would mitigate known vulnerabilities.

### F-0016 — 192.168.56.101:2121/tcp ftp

**Summary:** The observed service is ProFTPD version 1.3.1 running on port 2121 of host 192.168.56.101. This version of ProFTPD may be vulnerable to various security issues, such as buffer overflows or authentication bypass vulnerabilities that have been fixed in more recent versions. It is important to review the configuration for any insecure settings or misconfigurations which could allow unauthorized access.

**Next steps:**
- Review the ProFTPD configuration file (usually named 'proftpd.conf') for any insecure directives such as anonymous logins, weak passwords, or open shell transfers.
- Check if there are known vulnerabilities associated with this version of ProFTPD. You can use a tool like NVD (National Vulnerability Database) to find out if there are any known vulnerabilities that have not been patched in the observed version.
- Verify if the service is running on default ports or using non-standard ports, which could indicate a misconfiguration and potential exploitation.

### F-0017 — 192.168.56.101:3306/tcp mysql

**Summary:** The observed MySQL service on port 3306 is running an outdated version (5.0.51a-3ubuntu5) which exposes the system to potential security vulnerabilities that have been addressed in more recent versions of MySQL. The older version may lack critical security patches and features, making it vulnerable to a range of attacks including SQL injection, privilege escalation, and other common database-related exploits.

**Next steps:**
- Check for known vulnerabilities by comparing with the latest version (5.7.x or later) available in Ubuntu repositories.
- Review MySQL configuration files (my.cnf/my.ini) for any misconfigurations that could expose the service to unauthorized access, such as root login without a password and anonymous user creation.
- Perform a security audit of database permissions to identify if there are unnecessary privileges granted to users or roles.

### F-0018 — 192.168.56.101:5432/tcp postgresql

**Summary:** The observed service is PostgreSQL version 8.3.0 - 8.3.7 running on host 192.168.56.101 on port 5432/tcp. This version of PostgreSQL is quite old and may be vulnerable to known security issues such as outdated encryption methods, authentication vulnerabilities, or misconfigurations that could allow unauthorized access or data theft. The attack surface includes potential SQL injection attacks, privilege escalation, and insecure configuration settings.

### F-0020 — 192.168.56.101:6000/tcp X11

**Summary:** The observed service on port 6000/tcp is X11, which is a display server protocol used by Unix-like operating systems to provide graphical user interfaces. Given that the product and version are unspecified, it's unclear if this is a standard or custom implementation. The lack of specific details suggests potential vulnerabilities related to configuration issues or misconfigurations such as default settings or outdated libraries. 

### F-0022 — 192.168.56.101:8180/tcp 

**Summary:** The observed service on port 8180/tcp is a generic TCP listener without specific product or version information, which could be part of an application server, proxy, or any other network component. Given the lack of details, it's challenging to determine its exact function and security posture. However, this service might expose potential vulnerabilities if misconfigured or outdated. The attack surface includes possible unauthorized access through this port and a risk of being used in botnets or as part of a command-and-control (C2) infrastructure for malware.
