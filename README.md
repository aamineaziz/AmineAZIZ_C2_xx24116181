# AmineAZIZ_C2_xx24116181

# iPlanner
 iPlanner is a task management web application built using Flask.
 It includes role-based access control (RBAC) where admins can manage users task and users can manage their own tasks, and guest users can view tasks without modification rights.
 The application also includes logging for suspicious activities and errors.
## Prerequisites

Before running the iPlanner.py, make sure you have the following installed on your system:
- Python 3.x: [Download Python](https://www.python.org/downloads/)
- Flask: You can install Flask using `pip` by running the following command:
  ```bash
  pip install flask
  ```
- Flask-WTF
- SQLite3


## How to Run the this app

1. Clone this repository to your local machine.
    ```bash
    git clone <repository-url>
    cd <repository-folder>
    ```

2. Navigate to the folder of the app you want to run.

3. Start the Flask application by running the following command inside folder:
    ```bash
    python iPlanner.py
    ```

4. Open a browser and navigate to `http://127.0.0.1:8001/` to view the app.


## Folder Structure

file: iPlanner.py
file: TaskListDB.db
file: iPlanner.log
file: cert.csr
file: private.key
dir: static
	style.css
dir: templates
	homepage.html
	iPlanner.html
	newTask.html
	viewOnly.html
	404.html
	500.html
	
## Logging
The application logs suspicious activities and errors to `iPlanner.log`.
The logs include warnings for invalid input and error details for server issues.

## Security Features
- CSRF protection using Flask-WTF
- Content Security Policy (CSP) headers
- XSS, clickjacking, and content type sniffing protections
- Adding secure cookie and session handling to the login page.
- SQLi prevention

## **References for Further Learning**

1. **OWASP (Open Web Application Security Project)**:
   - **OWASP Top Ten Project**: [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
     - Provides a list of the top ten most critical web application security risks.
   - **OWASP Cheat Sheet Series**:
     - **XSS Prevention Cheat Sheet**: [https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
     - **Content Security Policy Cheat Sheet**: [https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_C_Cheat_Sheet.html)
     - **Session Management Cheat Sheet**: [https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_C_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_C_Cheat_Sheet.html)

2. **Flask Documentation**:
   - **Security Considerations**: [https://flask.palletsprojects.com/en/2.0.x/security/](https://flask.palletsprojects.com/en/2.0.x/security/)
     - Official Flask documentation on best security practices.
   - **Jinja2 Template Documentation**: [https://jinja.palletsprojects.com/en/3.0.x/templates/](https://jinja.palletsprojects.com/en/3.0.x/templates/)
     - Understanding how Jinja2 handles variable escaping and how to avoid XSS vulnerabilities.

3. **Mozilla Developer Network (MDN)**:
   - **Understanding Content Security Policy (CSP): [https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP](https://developer.mozilla.org/en-US/docs/CSP)
   - **XSS Prevention**: [https://developer.mozilla.org/en-US/docsCross-site_scripting](https://developer.mozilla.org/en-US/docs/Cross-site_scripting)

4. **Markupsafe Library**:
   - **Documentation**: [https://palletsprojects.com/p/markupsafe/](https://palletsprojects.com/p/markupsafe/)
     - Explains how `markupsafe.escape()` works to prevent XSS.

5. **PortSwWeb Security Tutorials**:
   - **PortSw Academy**: [https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)
     - Interactive labs and tutorials on XSS and other web.