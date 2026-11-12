# Class 8 Lab Report — IDOR Fix (NotesApp Flaw #7)

**Author:** CHEN YUCHEN (ENZO)  
**Student ID:** 2023905940  

---

## Hand-in Checklist

```text
IDOR FIX — NotesApp flaw #7 (broken access control) closed

Proof you got in:   as alice, /api/notes/3 returned bob's grade: 12.6 ("Solid work, keep it up.")
Fix:                api_notes refuses a note whose student_id is not the caller's,
                    unless the caller is a teacher/admin
Code chosen:        returns  [x] 404 not found   [ ] 403 forbidden
Proof it's closed:  as alice, /api/notes/3         -> {"error": "not found"} (404)
                    as alice, /api/notes/1         -> {"class_name": "Mathematics", "comment": "Late submission, but good quality.", "grade": 16.2, "id": 1, "student": "alice", "student_id": 6} (200 OK)
                    as prof.turing, /api/notes/3   -> {"class_name": "Mathematics", "comment": "Solid work, keep it up.", "grade": 12.6, "id": 3, "student": "bob", "student_id": 7} (200 OK)```

---

## Vulnerability & Fix Details

### 1. Root Cause (Broken Access Control / IDOR)
Previously, `/api/notes/<int:note_id>` in `web/app.py` verified authentication (`current_identity()`), confirming **who** the caller was, but failed to verify authorization (**what** records the caller was permitted to access). Any authenticated student could enumerate `note_id` values and read other students' grades and comments.

### 2. Implemented Fix (`web/app.py`)
Added an ownership and role check immediately after fetching the note record from PostgreSQL:

```python
    # Flaw #7 fix: 仅允许笔记本人、教师或管理员查看
    if note["student_id"] != ident.get("user_id") and ident.get("role") not in ("teacher", "admin"):
        return jsonify({"error": "not found"}), 404
```

### 3. Why `404 Not Found` Instead of `403 Forbidden`
Returning `404 Not Found` prevents unauthorized users from enumerating valid record IDs—an attacker cannot distinguish between a non-existent `note_id` and one belonging to another student.
