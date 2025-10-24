## Incident Postmortem: Spring4Shell Malware Attack on NBN Connection

### Summary

On March 20, 2022, at 03:21 UTC, the Telstra Security Operations Centre (SOC) detected a malware attack targeting the NBN Connection service, which operates on the Spring Framework 5.3.0. The incident was classified as P1 – Critical due to the service’s importance and the potential for widespread disruption.

The Security Operations Centre identified and triaged the threat, and the NBN Team was promptly notified to initiate incident response. The Networks Team later collaborated with the SOC to develop and deploy a firewall rule to block the malicious traffic.

The incident lasted approximately two hours, with full mitigation confirmed by 05:21 UTC once the firewall rule successfully stopped incoming exploit attempts.

Teams involved:

* Telstra Security Operations Centre (SOC)

* NBN Team

* Networks Team

Severity: P1 – Critical  
 Duration: 2 hours  
 Incident Window: 03:21 UTC – 05:21 UTC

### Impact

The attack impaired the NBN Connection service, resulting in partial loss of connectivity and degraded functionality for users relying on the network.  
 Although there was no confirmed data exfiltration or persistent compromise, the malware’s payload had the potential for remote code execution (RCE), which could have led to server takeover if left unmitigated.

The incident caused temporary downtime for a critical national service, increasing operational risk and triggering emergency response protocols.

### Detection

The SOC detected the incident through firewall log monitoring. Logs revealed a high frequency of HTTP POST requests to `/tomcatwar.jsp` from multiple distributed IP addresses (indicating a botnet-driven attack).  
 Payload inspection showed code attempting to exploit a known vulnerability in the Spring Framework (Spring4Shell, CVE-2022-22965), leveraging classloader parameters to inject a JSP webshell into the server’s `webapps/ROOT` directory.

### Root Cause

The root cause was the exploitation of an unpatched Spring Framework (version 5.3.0) used by the NBN Connection service.  
 Attackers exploited the Spring4Shell vulnerability, which allows remote code execution (RCE) by manipulating classloader resources through specially crafted POST requests.

The service had not yet been updated to a patched version of Spring Framework (5.3.18 or later), leaving it vulnerable to exploitation attempts once the vulnerability became public.

### Resolution

1. The SOC identified and confirmed the malicious traffic pattern.

2. The NBN Team was notified immediately to begin isolation procedures.

3. The Networks Team worked with the SOC to develop and deploy a Python-based simulated firewall rule that blocked:

   * POST requests to `/tomcatwar.jsp`

   * Any requests containing parameters matching  
      `class.module.classLoader.resources.context.*`

4. The rule was tested using controlled payloads (`test_requests.py`) to confirm it effectively blocked exploit attempts without disrupting legitimate traffic.

5. By 05:21 UTC, no further malicious requests were successfully processed, confirming containment of the attack.

### Action Items

Completed Actions:

* Implemented a custom firewall rule to block exploit signatures.

* Coordinated across SOC, Networks, and NBN teams for rapid response.

* Conducted a thorough log analysis to confirm attack patterns and origin.

Future Recommendations:

1. Patch Management: Immediately upgrade all Spring Framework instances to a patched version (≥ 5.3.18).

2. WAF Enhancement: Deploy pattern-based rules in the production firewall to detect similar RCE attempts.

3. Continuous Monitoring: Strengthen log correlation and anomaly detection alerts for rapid response to zero-day exploits.

4. Incident Training: Conduct a tabletop exercise for all teams on Java-based exploit responses.

5. Documentation: Archive this postmortem in the central governance repository for future audit and compliance reviews.

