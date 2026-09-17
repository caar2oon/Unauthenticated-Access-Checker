# Unauthenticated-Access-Checker
## Description
It automatically finds every endpoint your browser hits during a pentest, replays each one without your session cookie, and tells you whether the server still responds with real data flagging endpoints that may have broken authentication.

## Problem it solves
During a web application pentest, you need to manually verify that every protected page or API endpoint actually enforces authentication. Without a tool like this you would have to:

Manually copy each URL
Open an incognito window or delete cookies
Replay the request
Compare the response yourself

For an application with 200+ endpoints that process takes hours and is easy to miss things. This tool automates the entire workflow inside Burp Suite.
