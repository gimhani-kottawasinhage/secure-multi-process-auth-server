# Secure Multi-Process Authentication Server (C / Linux)

🚀 A secure client-server authentication system built in C as part of the IE2102 – Operating Systems coursework.  
The project demonstrates Linux system programming concepts with a focus on **authentication, concurrency, and process management**.

---

## 🔹 Key Features

- Multi-process server architecture using `fork()` (Linux)
- Custom TCP-based client-server communication
- Secure user registration and login system
- SHA-256 password hashing with salt
- Session token generation and validation
- Password policy enforcement
- Rate limiting for login attempts
- Account lockout after multiple failed attempts
- Protected commands requiring authentication
- Server-side logging and auditing
- Clean process lifecycle management (no zombie processes)

---

## 🔹 Concurrency Testing

- Concurrent client simulation implemented using **Python**
- Verified multi-client handling under load
- Ensured server stability with simultaneous connections

---

## 🎥 Demonstration
## 🎥 Demonstration Video

Watch the project demo here: https://mysliit-my.sharepoint.com/:f:/g/personal/it24103599_my_sliit_lk/IgDYmhn6pgLFQK44IfZxEnxAAS-GCANuvXEACjchhi6bDJQ?e=XycCrt

The system demo includes: 

- Server build and startup process
- Port verification using `ss`
- User registration and authentication flow
- Secure login with session token generation
- Protected resource access
- Failed login attempts and account lockout
- Concurrent client connections

---

## 🛠️ Technologies Used

- C (Programming Language)
- Linux System Programming
- TCP Sockets
- Unix System Calls
- SHA-256 Cryptographic Hashing
- Python (for concurrency testing)
- Operating Systems Concepts

---

## 💡 Key Learnings

- Linux process management using `fork()`
- Secure authentication system design
- Socket programming and client-server architecture
- Concurrency handling in server systems
- Practical cybersecurity principles (authentication, hashing, lockout mechanisms)

---

## 📌 Project Context

This project was developed for **IE2102 – Operating Systems**, focusing on real-world application of:

- Process creation and management
- Secure communication between client and server
- System-level programming in Linux

---

## 📎 Tags

#CProgramming #Linux #SocketProgramming #OperatingSystems #Cybersecurity #SystemsProgramming #Authentication #Python #BackendEngineering #ComputerScience
