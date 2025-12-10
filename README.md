# Encrypted File Storage System

This project is a mini cybersecurity tool designed to securely store and retrieve files using strong AES encryption. It converts any file into encrypted data that cannot be accessed without the correct password. The primary purpose of this system is to demonstrate the fundamentals of file encryption, key handling, and secure file storage using Python. The project also includes a simple user interface to make the application easier to use.

## Features

The system includes secure file encryption using AES (Advanced Encryption Standard) in CBC mode. It also supports safe decryption of stored files when the correct password is provided. The tool allows users to list all stored encrypted file IDs, delete a specific file, or delete all stored files. The program implements PKCS7 padding, activity logging, and automatic key and file management. A basic graphical user interface (UI) has been added to improve user experience.

## Technology Used

The project is implemented in Python and makes use of the following libraries:

* `cryptography` for AES encryption and hashing
* `uuid` for generating unique file identifiers
* `os` for file handling and folder management
* `getpass` for hidden password input
* `datetime` for activity logging
* `tkinter` for the optional graphical user interface

The cryptography module plays the most important role, as it handles key derivation, AES encryption, and secure decryption.

## How It Works

The user selects a file to store, provides a password, and the system encrypts the content using AES-256. Each stored file receives a unique ID, and both the encrypted data and the initialization vector (IV) are saved in separate secure folders. To retrieve a file, the user enters the file ID and the correct password. The system decrypts the content and restores the original file.

## Folder Structure

The system automatically creates the following directory structure:

* `SecureStorage/Encrypted` – stores encrypted files
* `SecureStorage/Keys` – stores the corresponding IVs
* `SecureStorage/activity.log` – maintains logs of encryption and decryption actions

This separation adds an additional layer of protection and improves the organization of the stored data.

## Requirements

Install the required libraries with:

```
pip install cryptography
```

Tkinter is included by default with most Python installations.

## Running the Project

To run the main console version:

```
python main.py
```

To run the UI version, execute the UI file you created, such as:

```
python ui.py
```
## Purpose of the Project

This project was created as part of a cybersecurity fundamentals course. The objective is to learn and demonstrate practical encryption, secure file handling, and the basic concepts of data confidentiality. It provides hands-on experience with cryptography and shows how secure storage systems are built in real-world applications.


