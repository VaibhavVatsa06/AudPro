import numpy as np
from pydub import AudioSegment
import tkinter as tk
from tkinter import filedialog, messagebox
import pygame
from scipy.signal import butter, lfilter

# Helper function to apply low-pass filter
def low_pass_filter(data, cutoff_freq, sample_rate):
    nyquist = 0.5 * sample_rate
    normal_cutoff = cutoff_freq / nyquist
    b, a = butter(1, normal_cutoff, btype='low', analog=False)
    filtered_data = lfilter(b, a, data)
    return filtered_data

def encode_audio(cover_audio_path, secret_audio_path, output_path, bits=2):
    cover_audio = AudioSegment.from_file(cover_audio_path, format="wav")
    secret_audio = AudioSegment.from_file(secret_audio_path, format="wav")

    cover_samples = np.array(cover_audio.get_array_of_samples())
    secret_samples = np.array(secret_audio.get_array_of_samples())

    if len(secret_samples) > len(cover_samples):
        raise ValueError("Secret audio is too large to hide in cover audio")

    # Make sure secret samples fit within cover samples
    secret_samples = np.pad(secret_samples, (0, len(cover_samples) - len(secret_samples)), 'constant')

    # Encode secret audio into the cover audio using multiple bits
    mask = (1 << bits) - 1
    encoded_samples = (cover_samples & ~mask) | ((secret_samples >> (16 - bits)) & mask)

    encoded_audio = cover_audio._spawn(encoded_samples.astype(np.int16).tobytes())
    encoded_audio.export(output_path, format="wav")

def decode_audio(encoded_audio_path, output_path, bits=2, cutoff_freq=1000):
    encoded_audio = AudioSegment.from_file(encoded_audio_path, format="wav")
    sample_rate = encoded_audio.frame_rate
    encoded_samples = np.array(encoded_audio.get_array_of_samples())

    # Decode secret audio from the cover audio using multiple bits
    mask = (1 << bits) - 1
    decoded_samples = ((encoded_samples & mask) << (16 - bits))

    # Apply low-pass filter to reduce noise
    decoded_samples = low_pass_filter(decoded_samples, cutoff_freq, sample_rate)

    decoded_audio = encoded_audio._spawn(decoded_samples.astype(np.int16).tobytes())
    decoded_audio.export(output_path, format="wav")

class AudioSteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Audio Steganography")

        # Initialize Pygame mixer
        pygame.mixer.init()

        # Encode Frame
        self.encode_frame = tk.Frame(root)
        self.encode_frame.pack(pady=10)

        self.cover_audio_label = tk.Label(self.encode_frame, text="Select Cover Audio: ")
        self.cover_audio_label.grid(row=0, column=0, padx=10, pady=10)

        self.cover_audio_path = tk.Entry(self.encode_frame, width=40)
        self.cover_audio_path.grid(row=0, column=1, padx=10, pady=10)

        self.cover_audio_button = tk.Button(self.encode_frame, text="Browse", command=self.browse_cover_audio)
        self.cover_audio_button.grid(row=0, column=2, padx=10, pady=10)

        self.secret_audio_label = tk.Label(self.encode_frame, text="Select Secret Audio: ")
        self.secret_audio_label.grid(row=1, column=0, padx=10, pady=10)

        self.secret_audio_path = tk.Entry(self.encode_frame, width=40)
        self.secret_audio_path.grid(row=1, column=1, padx=10, pady=10)

        self.secret_audio_button = tk.Button(self.encode_frame, text="Browse", command=self.browse_secret_audio)
        self.secret_audio_button.grid(row=1, column=2, padx=10, pady=10)

        self.output_label = tk.Label(self.encode_frame, text="Output File Name: ")
        self.output_label.grid(row=2, column=0, padx=10, pady=10)

        self.output_path = tk.Entry(self.encode_frame, width=40)
        self.output_path.grid(row=2, column=1, padx=10, pady=10)

        self.save_output_button = tk.Button(self.encode_frame, text="Save As", command=self.save_encoded_audio)
        self.save_output_button.grid(row=2, column=2, padx=10, pady=10)

        self.encode_button = tk.Button(self.encode_frame, text="Encode", command=self.encode_audio)
        self.encode_button.grid(row=3, column=1, padx=10, pady=10)

        self.play_encoded_button = tk.Button(self.encode_frame, text="Play Encoded Audio",
                                             command=self.play_encoded_audio)
        self.play_encoded_button.grid(row=4, column=1, padx=10, pady=10)

        # Decode Frame
        self.decode_frame = tk.Frame(root)
        self.decode_frame.pack(pady=10)

        self.encoded_audio_label = tk.Label(self.decode_frame, text="Select Encoded Audio: ")
        self.encoded_audio_label.grid(row=0, column=0, padx=10, pady=10)

        self.encoded_audio_path = tk.Entry(self.decode_frame, width=40)
        self.encoded_audio_path.grid(row=0, column=1, padx=10, pady=10)

        self.encoded_audio_button = tk.Button(self.decode_frame, text="Browse", command=self.browse_encoded_audio)
        self.encoded_audio_button.grid(row=0, column=2, padx=10, pady=10)

        self.decoded_output_label = tk.Label(self.decode_frame, text="Output File Name: ")
        self.decoded_output_label.grid(row=1, column=0, padx=10, pady=10)

        self.decoded_output_path = tk.Entry(self.decode_frame, width=40)
        self.decoded_output_path.grid(row=1, column=1, padx=10, pady=10)

        self.save_decoded_button = tk.Button(self.decode_frame, text="Save As", command=self.save_decoded_audio)
        self.save_decoded_button.grid(row=1, column=2, padx=10, pady=10)

        self.decode_button = tk.Button(self.decode_frame, text="Decode", command=self.decode_audio)
        self.decode_button.grid(row=2, column=1, padx=10, pady=10)

        self.play_decoded_button = tk.Button(self.decode_frame, text="Play Decoded Audio",
                                             command=self.play_decoded_audio)
        self.play_decoded_button.grid(row=3, column=1, padx=10, pady=10)

    def browse_cover_audio(self):
        self.cover_audio_path.delete(0, tk.END)
        filepath = filedialog.askopenfilename(filetypes=[("Audio Files", "*.wav")])
        self.cover_audio_path.insert(0, filepath)

    def browse_secret_audio(self):
        self.secret_audio_path.delete(0, tk.END)
        filepath = filedialog.askopenfilename(filetypes=[("Audio Files", "*.wav")])
        self.secret_audio_path.insert(0, filepath)

    def browse_encoded_audio(self):
        self.encoded_audio_path.delete(0, tk.END)
        filepath = filedialog.askopenfilename(filetypes=[("Audio Files", "*.wav")])
        self.encoded_audio_path.insert(0, filepath)

    def save_encoded_audio(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".wav", filetypes=[("Audio Files", "*.wav")])
        self.output_path.delete(0, tk.END)
        self.output_path.insert(0, filepath)

    def save_decoded_audio(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".wav", filetypes=[("Audio Files", "*.wav")])
        self.decoded_output_path.delete(0, tk.END)
        self.decoded_output_path.insert(0, filepath)

    def encode_audio(self):
        cover_audio = self.cover_audio_path.get()
        secret_audio = self.secret_audio_path.get()
        output_file = self.output_path.get()
        try:
            encode_audio(cover_audio, secret_audio, output_file)
            messagebox.showinfo("Success", "Audio encoded successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decode_audio(self):
        encoded_audio = self.encoded_audio_path.get()
        output_file = self.decoded_output_path.get()
        try:
            decode_audio(encoded_audio, output_file)
            messagebox.showinfo("Success", "Audio decoded successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def play_encoded_audio(self):
        encoded_audio_path = self.output_path.get()
        if encoded_audio_path:
            pygame.mixer.music.load(encoded_audio_path)
            pygame.mixer.music.play()
        else:
            messagebox.showerror("Error", "No encoded audio file specified.")

    def play_decoded_audio(self):
        decoded_audio_path = self.decoded_output_path.get()
        if decoded_audio_path:
            pygame.mixer.music.load(decoded_audio_path)
            pygame.mixer.music.play()
        else:
            messagebox.showerror("Error", "No decoded audio file specified.")


if __name__ == "__main__":
    root = tk.Tk()
    app = AudioSteganographyApp(root)
    root.mainloop()