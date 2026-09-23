# Draft: VPN Options (Research, Presentation, and Non-Technical Guide)

**Deliverables beyond the memo:**
1. **A 3-minute recorded presentation on YouTube** comparing 3 VPN solutions and justifying the choice.
2. **A link to the presentation slide deck** (the Canvas grader explicitly penalized submissions that only linked YouTube and omitted the slides).
3. **A written research and comparison section inside the memo itself** (the grader penalized submissions that only discussed research in the video).
4. **An illustrated, step-by-step user guide** tailored to non-technical employees (download, installation, SSO authentication, and daily tray operation).

---

## Pre-competition preparation (do this BEFORE Saturday)

- **Create an unlisted video placeholder or recording setup:** Have OBS, QuickTime, or simple screen recording ready on your workstation.
- **The 3-minute script below is timed and ready to read.** You can record the video in ~3 minutes using the script in Section 2, upload as "Unlisted" to YouTube, and paste the URL.
- **Have a simple Google Slides / PowerPoint deck ready** with 4 slides matching the script (Problem/Options, Comparison, Tailscale Architecture, Non-Tech Workflow). Export a shareable link or PDF.

---

```text
INTEROFFICE MEMORANDUM

To:      Kaden Liu, Chief Operating Officer
From:    Team <XX>
Date:    <DATE>
Subject: Secure VPN Options: Evaluation, Recommendation, and User Guide

Summary: In response to executive leadership's request to enable secure remote
         work capabilities for all employees, we evaluated three enterprise
         VPN solutions: Tailscale, OpenVPN Access Server, and Cloudflare Zero
         Trust. Based on zero-trust security architecture, perimeter attack
         surface reduction, and end-user simplicity, we selected and deployed
         Tailscale. Below is our formal comparative research analysis, a link
         to our recorded 3-minute executive presentation and slide deck, and a
         complete, illustrated user guide for non-technical staff.

1. Research and Evaluation of Three VPN Solutions

   We evaluated three industry-standard remote access solutions against four
   core business criteria: security architecture, perimeter firewall exposure,
   administrative maintenance, and ease of use for non-technical employees.

   | Evaluation Criteria | Tailscale (Selected) | OpenVPN Access Server | Cloudflare Zero Trust (WARP) |
   |---|---|---|---|
   | Cryptographic Protocol | WireGuard (state-of-the-art noise protocol, ChaCha20-Poly1305) | OpenSSL / TLS / OpenVPN custom | WireGuard-based (Cloudflare BoringTun) |
   | Perimeter Attack Surface | ZERO open inbound firewall ports. Direct mesh connections negotiated via outbound NAT traversal (STUN/DERP). | Requires opening and port-forwarding inbound UDP 1194 on company perimeter router. | ZERO open inbound ports (outbound tunnel to Cloudflare edge). |
   | Authentication & Identity | Seamless Single Sign-On (SSO) integration with Google Workspace / Microsoft 365. Enforces corporate MFA. | Requires internal PKI, individual user certificates (.ovpn files), or RADIUS/LDAP sync. | SSO integration via Cloudflare Access dashboard and IdP tokens. |
   | Non-Technical User Experience | Single-click desktop tray icon; automatic SSO login; no server addresses or configs to type. | Complex configuration profiles (.ovpn); manual certificate importing; multi-step reconnects. | Client application (WARP); user enters organization team domain during onboarding. |
   | Infrastructure & Maintenance | Zero VPN concentrator servers to patch or maintain; mesh peer-to-peer routing. | Requires dedicated VM/server concentrator, ongoing Linux patching, and certificate expiration tracking. | Cloud-hosted control plane; requires routing internal subnets through Cloudflare cloud edge. |

2. Rationale for Selecting Tailscale

   Following the remote access guidelines in NIST Special Publication 800-77
   Revision 1, Guide to Enterprise Telework, Remote Access, and TLS IPsec VPNs
   (https://csrc.nist.gov/pubs/sp/800/77/r1/final), we prioritized minimizing
   the organization's external attack surface and eliminating user friction.

   Tailscale is our recommended and selected solution for three primary reasons:

   a. Zero Inbound Perimeter Exposure: Traditional VPNs like OpenVPN require
      opening an inbound port on our perimeter firewall (UDP 1194). This
      exposes an administrative listening service to continuous port scanning,
      denial-of-service, and remote zero-day exploit attempts. Tailscale uses
      outbound-only peer-to-peer NAT traversal; company servers and remote
      laptops establish secure tunnels without exposing any public listening
      ports to the open internet.

   b. Identity-First Access Control: Rather than managing fragile static
      encryption certificates or sharing VPN passwords, Tailscale binds device
      authorization directly to our existing corporate identity provider
      (Microsoft 365 or Google Workspace). When an employee authenticates,
      they inherit existing corporate Multi-Factor Authentication (MFA)
      policies. If an employee leaves the company, revoking their email
      account instantly revokes their VPN access.

   c. Minimal Employee Friction: OpenVPN requires non-technical staff to
      download cryptographic configuration files and certificates, frequently
      causing connection failures. Tailscale installs as a lightweight background
      utility that authenticates through a standard corporate web browser
      prompt.

3. Executive Presentation and Video Deliverables

   As requested, our team recorded a 3-minute executive presentation summarizing
   this research, demonstrating the client connection, and detailing the
   rollout plan.

   - Video Presentation URL: https://youtu.be/<VIDEO_ID>
     *(Note: Closed captions / subtitles and full audio transcript are enabled)*
   - Presentation Slide Deck: <https://docs.google.com/presentation/d/... or attached SLIDES.pdf>

   Presentation Outline:
   - 0:00 - 0:45: Business context, remote work security risks, and options evaluated.
   - 0:45 - 1:45: Architecture comparison: Inbound attack surface vs. outbound WireGuard mesh.
   - 1:45 - 2:30: Live demonstration of employee connection and SSO MFA enforcement.
   - 2:30 - 3:00: Implementation timeline, cost overview, and IT support contact.

4. Non-Technical Employee User Guide: Getting Started with Tailscale

   ------------------------------------------------------------------
   WHAT IS A VPN? (IN PLAIN ENGLISH)
   A Virtual Private Network (VPN) creates a private, encrypted digital
   tunnel between your laptop and our company's internal servers. When you
   work from home, a hotel, or a coffee shop, public Wi-Fi can expose your
   network traffic to eavesdropping. Tailscale protects your data with
   military-grade encryption so you can securely access company files and
   applications from anywhere in the world.
   ------------------------------------------------------------------

   STEP 1: DOWNLOAD AND INSTALLATION
   1. Open your web browser and navigate to the official installation page:
      https://tailscale.com/download
   2. Click the download button for your computer (Windows, macOS, or Linux).
   3. Open the downloaded installation file (for example, `tailscale-setup.exe`
      on Windows) and follow the on-screen prompts to complete installation.
   4. Once installed, a small Tailscale icon (three white dots) will appear in
      your system notification area (near the clock on the bottom-right of
      Windows or top-right of macOS).

      [Figure 1: Tailscale Installation Confirmation and System Tray Location]

   STEP 2: FIRST-TIME SETUP AND SIGN-IN
   1. Click the Tailscale icon in your system tray or menu bar and select
      "Log in...".
   2. Your default web browser will automatically open to our corporate login
      portal.
   3. Click "Sign in with Microsoft" (or "Sign in with Google") and enter your
      standard company email address and password.
   4. Approve the Multi-Factor Authentication (MFA) notification sent to your
      authenticator app or mobile device.
   5. A confirmation screen will appear saying "Success! Device connected."
      You may now close your browser.

      [Figure 2: Corporate SSO Web Login and Device Approval Screen]

   STEP 3: EVERYDAY USE AND CONNECTION STATUS
   Tailscale is designed to work quietly in the background without getting in
   your way:
   - Connected (Working Securely): The Tailscale system tray icon is SOLID
     white or dark grey. All internal company applications and network drives
     will open automatically.
   - Disconnected: The Tailscale system tray icon is FAINT or hollow.
   - To Connect or Disconnect: Simply click the Tailscale icon in the system
     tray. The top of the menu displays your connection status with an on/off
     toggle switch. Click "Connect" when beginning your workday, and
     "Disconnect" when personal use is desired.

      [Figure 3: System Tray Status Menu Showing Active Connection]

   STEP 4: NEED HELP?
   If you experience connection difficulties, please verify your internet
   connection, right-click the Tailscale icon, and select "Restart Tailscale".
   If issues persist, submit a ticket to the IT & Security Helpdesk at
   <helpdesk@company.com> or reach Team <XX> in the administrative portal.

5. Sources Cited

   - NIST Special Publication 800-77 Revision 1: Guide to Enterprise Telework,
     Remote Access, and TLS IPsec VPNs:
     https://csrc.nist.gov/pubs/sp/800/77/r1/final
   - Tailscale Architecture, Security, and WireGuard Protocol:
     https://tailscale.com/security
   - OpenVPN Access Server Architecture & Deployment Guide:
     https://openvpn.net/access-server/
   - Cloudflare Zero Trust Documentation:
     https://developers.cloudflare.com/cloudflare-one/

If there are any concerns, questions, or clarifications, please do not
hesitate to reach out.

Best regards,
Team <XX>
```

---

## 3-Minute Video Script (for operator recording)

If asked to produce or present the 3-minute video on competition day, use this script word-for-word:

> **[Slide 1 - Title: Secure Remote Access & VPN Options | Team XX] (0:00 - 0:40)**
> "Hello management team. Today we are presenting our evaluation and recommendation for securing remote employee access across our enterprise. As our workforce operates remotely, protecting internal company data and customer records from untrusted external networks is a top priority. We analyzed three industry-leading solutions: OpenVPN Access Server, Cloudflare Zero Trust, and Tailscale."

> **[Slide 2 - Solution Comparison] (0:40 - 1:20)**
> "Traditional VPNs like OpenVPN rely on open inbound firewall ports. Exposing port 1194 to the entire internet creates an immediate target for brute-force attacks and vulnerability scanning. Furthermore, distributing cryptographic certificates to non-technical users causes high administrative overhead. Cloudflare Zero Trust offers strong cloud routing, but introduces recurring external SaaS dependencies and complex edge tunnel routing. Tailscale, by contrast, uses a decentralized peer-to-peer mesh architecture built on modern WireGuard cryptography."

> **[Slide 3 - Why Tailscale Wins] (1:20 - 2:10)**
> "Tailscale was selected for three reasons. First, security: it requires zero open inbound firewall ports. Direct connections are established using outbound NAT traversal, closing our perimeter to outside scanners. Second, identity integration: Tailscale binds directly to our corporate Google Workspace or Microsoft 365 accounts, inheriting our existing Multi-Factor Authentication. Third, usability: employees authenticate once in their web browser with no configuration files or server IP addresses to memorize."

> **[Slide 4 - Employee Experience & Rollout] (2:10 - 3:00)**
> "For our staff, daily operation requires zero technical knowledge. We have provided an illustrated, 3-step user guide: install the client, sign in with corporate credentials, and connect directly from the system tray icon. All traffic across the tunnel is encrypted with ChaCha20-Poly1305. The full written evaluation, slide deck, and employee guide are detailed in our memorandum. Thank you, and we welcome any questions."
