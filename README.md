# Unauthenticated-Access-Checker
## Description
It automatically finds every endpoint your browser hits during a pentest, replays each one without your session cookie, and tells you whether the server still responds with real data flagging endpoints that may have broken authentication.

## Problem
During a web application pentest, you need to manually verify that every protected page or API endpoint actually enforces authentication. Without a tool like this you would have to:

Manually copy each URL
Open an incognito window or delete cookies
Replay the request
Compare the response yourself

For an application with 200 or 300+ endpoints that process takes hours and is easy to miss things. This tool automates the entire workflow inside Burp Suite.

## What it does ?
While you browse a web application normally through Burp Proxy, the extension captures every endpoint in the background. When you trigger a check, it strips your session cookies and auth headers from the original request, replays it without authentication, and compares the two responses to determine whether the endpoint is protected.

## How to use
1. Log in to the application and browse around normally with Burp Proxy running. The extension will automatically capture endpoints from live traffic as you go.
2. If you have already been browsing before loading the extension:
   a. Go to the Unauth Checker tab
   b. Click Import History
   c. Wait for the progress bar to complete
  All endpoints from Burp's proxy history will be loaded into the table.
3. Check specific endpoints:
   a. Click on one or more rows in the table
   b. Click Check Selected
4. Check the Result column:

    PROTECTED is authentication is enforced

    ACCESSIBLE means without authentication the endpoint is accessible

    POSSIBLY_ACCESSIBLE	require manually confirmation of tester

    INCONCLUSIVE means send to Repeater for manual testing it basically for 302, 301, 101 requests

6. You can click the Unauth Request tab to confirm the session cookie was removed
7. Use the Result Filter dropdown to focus on ACCESSIBLE or POSSIBLY_ACCESSIBLE
8. Click Export CSV to save results

## POC
<img width="1924" height="474" alt="image" src="https://github.com/user-attachments/assets/61bffb5d-1d27-48fd-a951-6575cb4f641a" />
<img width="1924" height="889" alt="image" src="https://github.com/user-attachments/assets/b0f01790-aafc-4c3c-8dd3-76c7d22f4826" />

