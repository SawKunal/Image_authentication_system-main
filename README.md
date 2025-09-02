# Image_authentication_system-main
🖼️ Image Authentication System

A Python-based GUI application for secure authentication using steganography and encryption.
Passwords are hidden inside images using Particle Swarm Optimization (PSO) and cryptographic techniques, making authentication more secure than traditional text-based logins.

✨ Features

🔐 User Signup & Login with image-based password storage

🖼️ Steganography: Embeds passwords in images at optimized pixel positions

⚡ Particle Swarm Optimization (PSO) for minimal distortion embedding

🔑 PBKDF2 password hashing and AES-based encryption (Fernet) for secure credential storage

🖥️ GUI built with Tkinter for easy interaction

✅ Secure authentication via extracted hidden password

🛠️ Tech Stack

Python 3.x

OpenCV
 – Image processing

Pillow (PIL)
 – Image handling

Cryptography
 – Encryption & hashing

Tkinter – GUI framework

NumPy, JSON, base64, secrets – Supporting libraries

📂 Project Structure
Image_authentication_system/
│── main.py                 # Main application code (signup & login)
│── auth_data.json          # Stores hashed credentials
│── encryption_key.key      # Auto-generated encryption key
│── *_stego.png/.jpg        # Generated stego images (user password embedded)
│── *_positions.enc         # Encrypted pixel positions for password retrieval

🚀 Installation

Clone the repository

git clone https://github.com/your-username/Image_authentication_system.git
cd Image_authentication_system


Install dependencies

pip install opencv-python pillow cryptography


Run the application

python main.py

🎮 Usage
🔑 Signup

Enter a username & password

Select an image (PNG/JPG)

Application generates a stego image containing your password + encrypted pixel positions

Use this image for future logins

🔓 Login

Enter your username

Select the previously generated stego image

Password is extracted and verified securely

📸 Screenshots

(Add screenshots of your Signup and Login windows here)

🔒 Security Highlights

Passwords never stored in plain text

PBKDF2 HMAC with SHA256 for hashing

Encrypted pixel positions for stego retrieval

Stop markers used to ensure safe password extraction

📜 License

This project is licensed under the MIT License – feel free to use, modify, and distribute.
