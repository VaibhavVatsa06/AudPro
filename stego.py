import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from pydub import AudioSegment
import numpy as np
import librosa
import wave
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64
import io

class AudioSteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Audio Steganography")
        self.root.geometry("800x600")  # Set window size

        self.file_path = ""
        self.processed_audio_path = "processed_audio.wav"
        self.stego_audio_path = "stego_audio.wav"
        self.security_key = None

        # Load background image
        bg_image_path = r"C:\Users\singh\Downloads\bg.jpg"
        bg_image = Image.open(bg_image_path)
        bg_image = bg_image.resize((800, 600), Image.LANCZOS)
        self.bg_photo = ImageTk.PhotoImage(bg_image)
        self.bg_label = tk.Label(root, image=self.bg_photo)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Create main frame
        self.main_frame = tk.Frame(root, bg='white', bd=0)  # Set bd=0 to remove frame border
        self.main_frame.place(relx=0.5, rely=0.5, anchor='center', width=700, height=500)

        # Title label
        self.label = tk.Label(self.main_frame, text="Audio Steganography", font=("Arial", 24), bg='white')
        self.label.pack(pady=20)

        # Upload button
        self.upload_button = tk.Button(self.main_frame, text="Upload Audio", command=self.upload_audio, font=('Arial', 14))
        self.upload_button.pack(pady=10)

        # Process button
        self.process_button = tk.Button(self.main_frame, text="Process Audio", command=self.process_audio_btn, font=('Arial', 14))
        self.process_button.pack(pady=10)

        # Embed Message button
        self.embed_message_button = tk.Button(self.main_frame, text="Embed Message", command=self.embed_message_btn, font=('Arial', 14))
        self.embed_message_button.pack(pady=10)

        # Extract Message button
        self.extract_message_button = tk.Button(self.main_frame, text="Extract Message", command=self.extract_message_btn, font=('Arial', 14))
        self.extract_message_button.pack(pady=10)

        # Embed Image button
        self.embed_image_button = tk.Button(self.main_frame, text="Embed Image", command=self.embed_image_btn, font=('Arial', 14))
        self.embed_image_button.pack(pady=10)

        # Extract Image button
        self.extract_image_button = tk.Button(self.main_frame, text="Extract Image", command=self.extract_image_btn, font=('Arial', 14))
        self.extract_image_button.pack(pady=10)

    def upload_audio(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("WAV files", "*.wav")])
        if self.file_path:
            messagebox.showinfo("File Selected", f"Selected file: {self.file_path}")

    def process_audio_btn(self):
        if self.file_path:
            process_audio(self.file_path, self.processed_audio_path)
            self.security_key = extract_features(self.processed_audio_path)
            messagebox.showinfo("Processing Complete", f"Audio processed.\nSecurity Key: {self.security_key}")
        else:
            messagebox.showwarning("No File", "Please upload an audio file first.")

    def embed_message_btn(self):
        if self.file_path:
            message = simpledialog.askstring("Input", "Enter the message to embed:")
            if message:
                key = simpledialog.askstring("Input", "Enter a 16-byte encryption key (e.g., 1234567890123456):")
                if len(key) == 16:
                    embed_message(self.processed_audio_path, message, self.stego_audio_path, key.encode())
                    messagebox.showinfo("Embedding Complete", "Message embedded into audio.")
                else:
                    messagebox.showwarning("Invalid Key", "Encryption key must be 16 bytes long.")
        else:
            messagebox.showwarning("No File", "Please upload an audio file first.")

    def extract_message_btn(self):
        if self.file_path:
            key = simpledialog.askstring("Input", "Enter the 16-byte encryption key:")
            if len(key) == 16:
                extracted_key = extract_features(self.processed_audio_path)
                if np.allclose(extracted_key, self.security_key):
                    hidden_message = extract_message(self.stego_audio_path, key.encode())
                    messagebox.showinfo("Extracted Message", f"Hidden message: {hidden_message}")
                else:
                    messagebox.showwarning("Verification Failed", "The security key does not match. Extraction failed.")
            else:
                messagebox.showwarning("Invalid Key", "Encryption key must be 16 bytes long.")
        else:
            messagebox.showwarning("No File", "Please upload an audio file first.")

    def embed_image_btn(self):
        if self.file_path:
            image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
            if image_path:
                key = simpledialog.askstring("Input", "Enter a 16-byte encryption key (e.g., 1234567890123456):")
                if len(key) == 16:
                    embed_image(self.processed_audio_path, image_path, self.stego_audio_path, key.encode())
                    messagebox.showinfo("Embedding Complete", "Image embedded into audio.")
                else:
                    messagebox.showwarning("Invalid Key", "Encryption key must be 16 bytes long.")
        else:
            messagebox.showwarning("No File", "Please upload an audio file first.")

    def extract_image_btn(self):
        if self.file_path:
            key = simpledialog.askstring("Input", "Enter the 16-byte encryption key:")
            if len(key) == 16:
                extracted_key = extract_features(self.processed_audio_path)
                if np.allclose(extracted_key, self.security_key):
                    hidden_image = extract_image(self.stego_audio_path, key.encode())
                    if hidden_image.startswith("Error"):
                        messagebox.showwarning("Extraction Failed", hidden_image)
                    else:
                        try:
                            image = Image.open(io.BytesIO(base64.b64decode(hidden_image)))
                            image.show()
                        except Exception as e:
                            messagebox.showwarning("Image Display Error", f"Error displaying image: {e}")
                else:
                    messagebox.showwarning("Verification Failed", "The security key does not match. Extraction failed.")
            else:
                messagebox.showwarning("Invalid Key", "Encryption key must be 16 bytes long.")
        else:
            messagebox.showwarning("No File", "Please upload an audio file first.")

def process_audio(input_path, output_path):
    audio = AudioSegment.from_wav(input_path)
    audio = audio.set_channels(1)
    audio.export(output_path, format='wav')

def extract_features(audio_path):
    y, sr = librosa.load(audio_path, sr=None)
    mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
    security_key = np.mean(mfccs, axis=1)
    return security_key

def pad_message(message):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    return padded_data

def unpad_message(padded_message):
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_message) + unpadder.finalize()
    return data

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = pad_message(message)
    encrypted_message = iv + encryptor.update(padded_message) + encryptor.finalize()
    return encrypted_message

def decrypt_message(encrypted_message, key):
    try:
        iv = encrypted_message[:16]
        encrypted_message = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
        message = unpad_message(padded_message)
        return message.decode()
    except Exception as e:
        return f"Error during decryption: {e}"

def embed_message(audio_path, message, output_path, key):
    encrypted_message = encrypt_message(message, key)
    binary_message = ''.join(format(byte, '08b') for byte in encrypted_message) + '1111111111111110'
    audio = wave.open(audio_path, 'rb')
    frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

    for i in range(len(binary_message)):
        frame_bytes[i] = (frame_bytes[i] & 254) | int(binary_message[i])

    with wave.open(output_path, 'wb') as new_audio:
        new_audio.setparams(audio.getparams())
        new_audio.writeframes(frame_bytes)

    audio.close()

def extract_message(stego_audio_path, key):
    try:
        audio = wave.open(stego_audio_path, 'rb')
        frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

        extracted_bits = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]
        binary_message = ''.join(map(str, extracted_bits))

        message_bytes = [binary_message[i: i + 8] for i in range(0, len(binary_message), 8)]
        extracted_data = bytes([int(byte, 2) for byte in message_bytes])

        delimiter_index = extracted_data.find(b'\xFF\xFE')
        if delimiter_index != -1:
            encrypted_message = extracted_data[:delimiter_index]
            return decrypt_message(encrypted_message, key)
        return "No hidden message found"
    except Exception as e:
        print(f"Error during extraction: {e}")
        return "Error during extraction."

def embed_image(audio_path, image_path, output_path, key):
    with open(image_path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
    encrypted_message = encrypt_message(encoded_string.decode(), key)
    binary_message = ''.join(format(byte, '08b') for byte in encrypted_message) + '1111111111111110'
    audio = wave.open(audio_path, 'rb')
    frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

    for i in range(len(binary_message)):
        frame_bytes[i] = (frame_bytes[i] & 254) | int(binary_message[i])

    with wave.open(output_path, 'wb') as new_audio:
        new_audio.setparams(audio.getparams())
        new_audio.writeframes(frame_bytes)

    audio.close()

def extract_image(stego_audio_path, key):
    try:
        audio = wave.open(stego_audio_path, 'rb')
        frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

        extracted_bits = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]
        binary_message = ''.join(map(str, extracted_bits))

        message_bytes = [binary_message[i: i + 8] for i in range(0, len(binary_message), 8)]
        extracted_data = bytes([int(byte, 2) for byte in message_bytes])

        delimiter_index = extracted_data.find(b'\xFF\xFE')
        if delimiter_index != -1:
            encrypted_message = extracted_data[:delimiter_index]
            decrypted_message = decrypt_message(encrypted_message, key)
            return decrypted_message
        return "No hidden image found"
    except Exception as e:
        print(f"Error during extraction: {e}")
        return "Error during extraction."

if __name__ == "__main__":
    root = tk.Tk()
    app = AudioSteganographyApp(root)
    root.mainloop()
