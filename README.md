# InsecPy

## Description
**InsecPy** is a simple Python tool designed to perform a website vulnerability scan. This tool will utilize Python libraries and modules to analyse the target website for potential security vulnerabilities.

## Features
- This tool will perform various vulnerability scans, which includes in :
   - SQL injection
   - XSS 
   - Open Redirects
   - Cookie Security


## Installation

### Prerequisites
- Python 3.x
- pip (Python package installer)

### Steps to Install
1. Clone the repository:
   ```bash
   git clone https://github.com/RAKESH-PALADUGU/InsecPy.git
2. Open downloaded Directory :
   ```bash
   cd InsecPy
3. Create Virtual Environment :
   ```bash
   python3 -m venv myvenv
4. Activate Virtual Environment :

   - for WINDOWS :
      ```bash
      myvenv\scripts\activate
   - for macOS/Linux :
      ```bash
      source myvenv/bin/activate
5. Install the required dependencies :
   ```bash 
   pip install -r requirements.txt
6. Run the tool :
   ```bash
   python3 InsecPy.py
7. Deactivate the Virtual Environment :
   ```bash
   deactivate
---

### NOTE : Always use a Virtual Environment to keep your project dependencies isolated from your global Python installation. This helps avoid conflicts between different projects.
