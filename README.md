# Secure File Sharing System

This project is a secure file upload and download portal built with **Python Flask**. It uses the **AES (Advanced Encryption Standard)** algorithm to protect files both at rest and in transit.

## Security Overview

The system is designed with the following security principles:

-   **Data at Rest Encryption:** Files are encrypted with **AES-256** using **CBC mode** before being stored on the server. The original, unencrypted file is immediately deleted after encryption, ensuring that no sensitive data is left exposed.
-   **Data in Transit Protection:** While the application uses a basic HTTP server for local development, in a production environment, it would be deployed with **HTTPS (SSL/TLS)**. The file content itself is also encrypted, which provides an additional layer of security.
-   **Secure File Handling:** The application never stores a decrypted version of the file on the server. During a download, the file is decrypted and streamed to the user. A temporary decrypted file is created only to be served and is immediately deleted afterward.
-   **Key Management:** The encryption key is derived from a hardcoded secret. **NOTE:** For a real-world application, this key would be managed using a secure key management system (KMS) and never stored in the code.
-   **Authentication:** This project focuses on encryption and secure handling. A production-ready system would require robust user authentication to control file access.

## Getting Started

To run this application, you need Python and pip installed.

1.  **Clone the Repository:**
    `git clone <your_github_repo_url>`

2.  **Set Up the Virtual Environment:**
    `cd Secure File Sharing System`
    `python3 -m venv venv`
    `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)

3.  **Install Dependencies:**
    `pip install Flask pycryptodome`

4.  **Run the Application:**
    `python app.py`

The application will be accessible at `http://127.0.0.1:5000`.

## Deliverables

-   **GitHub Repository:** [Link to this repo]
-   **Walkthrough Video:** [Link to your video]
-   **Security Overview Document:** This `README.md` file serves as the document.