# Class 9 Lab Report: Injection Vulnerabilities and Remediation

**Course:** EPITA Computer Security Course  
**Status:** Completed  

---

## 1. Overview
This laboratory focuses on identifying, exploiting, and fixing two critical injection vulnerabilities within the NotesApp web application:
1. **SQL Injection (SQLi)** in the user authentication mechanism (`/login`).
2. **OS Command Injection** in the administrator network diagnostic feature (`/admin/ping`).

---

## 2. Part 1: SQL Injection in Login

### Vulnerability Analysis
In the original implementation of the `/login` route (`web/app.py`), the username supplied by the user was concatenated directly into the SQL query string:
```python
query = (
    "SELECT id, username, role, password FROM users "
    "WHERE username = '" + username + "'"
)
```
This allowed an attacker to manipulate the query syntax by injecting SQL control characters (e.g., `admin' -- `), terminating the condition early, and bypassing password authentication.

### Remediation
We replaced the vulnerable string concatenation with a **parameterized query** (`cursor.execute(query, (username,))`). This ensures that the database driver treats user input strictly as a literal data parameter rather than executable SQL syntax.

---

## 3. Part 2: OS Command Injection in Admin Ping

### Vulnerability Analysis
In the original `/admin/ping` route, the `host` parameter was directly concatenated into a shell command string, and executed with `shell=True`:
```python
cmd = "ping -c 1 " + host
result = subprocess.run(cmd, shell=True, ...)
```
This allowed an attacker with administrator privileges to append arbitrary shell commands using chaining characters (e.g., `; id`, `&& whoami`), leading to Remote Code Execution (RCE) on the underlying server container.

### Remediation
We secured this feature by completely removing `shell=True` and passing the command arguments as a list to `subprocess.run`:
```python
result = subprocess.run(
    ["ping", "-c", "1", host], shell=False, capture_output=True, text=True, timeout=10,
)
```
This prevents the shell from interpreting operators like `;`, `&&`, or `|`, safely treating the entire input string as a single argument for the `ping` utility.

---

## 4. Verification and Testing

After applying the code updates in `web/app.py` and rebuilding the Docker containers (`docker compose up --build -d`):
* **SQL Injection Test:** Attempting to log in with `admin' -- ` now correctly fails, as the database treats the literal string as the username parameter and finds no matching record.
* **Command Injection Test:** Attempting to input `; id` into the admin ping form no longer executes secondary shell commands; instead, it safely passes the string to `ping`, which rejects it as an invalid host.