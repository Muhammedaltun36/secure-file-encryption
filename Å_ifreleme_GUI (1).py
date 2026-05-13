import tkinter as tk
from tkinter import filedialog, messagebox
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

# --- ENGINE (MOTOR) FONKSİYONLARI ---

def anahtar_uret():
    key = RSA.generate(2048)
    with open("private.pem", "wb") as f: f.write(key.export_key())
    with open("public.pem", "wb") as f: f.write(key.publickey().export_key())
    return "Anahtarlar Üretildi (public.pem, private.pem)"

def hibrit_sifrele(dosya_yolu, sifre):
    # Anahtar Türetme
    hash_obj = SHA256.new(sifre.encode('utf-8'))
    aes_key = hash_obj.digest() 

    # RSA Zarfı Oluşturma
    alici_key = RSA.import_key(open("public.pem").read())
    rsa_cipher = PKCS1_OAEP.new(alici_key)
    zarf = rsa_cipher.encrypt(aes_key)

    # AES Şifreleme
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    with open(dosya_yolu, "rb") as f:
        sifreli_veri = aes_cipher.encrypt(pad(f.read(), AES.block_size))

    with open(dosya_yolu + ".hibrit", "wb") as f:
        f.write(zarf + aes_cipher.iv + sifreli_veri)
    return f"Dosya Şifrelendi: {os.path.basename(dosya_yolu)}.hibrit"

def hibrit_coz(dosya_yolu):
    with open(dosya_yolu, "rb") as f:
        zarf = f.read(256)
        iv = f.read(16)
        sifreli_veri = f.read()

    # Zarfı Açma
    gizli_key = RSA.import_key(open("private.pem").read())
    rsa_cipher = PKCS1_OAEP.new(gizli_key)
    aes_key = rsa_cipher.decrypt(zarf)

    # Veriyi Çözme
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    cozulmus = unpad(aes_cipher.decrypt(sifreli_veri), AES.block_size)

    cikti_yolu = dosya_yolu.replace(".hibrit", "_cozulmus.txt")
    with open(cikti_yolu, "wb") as f: f.write(cozulmus)
    return f"Dosya Çözüldü: {os.path.basename(cikti_yolu)}"

# --- ARAYÜZ (GUI) TASARIMI ---

class SifrelemeApp:
    def __init__(self, pencere):
        self.pencere = pencere
        self.pencere.title("B.O.E.Ü. Güvenli Dosya Şifreleme")
        self.pencere.geometry("450x400")
        self.pencere.configure(bg='#1e293b') # Koyu tema (Sunumdaki gibi)

        # Başlık
        tk.Label(pencere, text="DİJİTAL ZARF SİSTEMİ", font=("Arial", 16, "bold"), fg="#38bdf8", bg="#1e293b").pack(pady=20)

        # Butonlar
        btn_style = {"font": ("Arial", 10, "bold"), "width": 25, "height": 2, "cursor": "hand2"}
        
        tk.Button(pencere, text="1. RSA ANAHTARLARI ÜRET", command=self.btn_anahtar, bg="#34d399", **btn_style).pack(pady=10)
        
        tk.Label(pencere, text="AES Parolası (Zarf İçi):", fg="white", bg="#1e293b").pack()
        self.sifre_entry = tk.Entry(pencere, show="*", width=30)
        self.sifre_entry.pack(pady=5)

        tk.Button(pencere, text="2. DOSYA ŞİFRELE (.hibrit)", command=self.btn_sifrele, bg="#38bdf8", **btn_style).pack(pady=10)
        tk.Button(pencere, text="3. ŞİFRE ÇÖZ", command=self.btn_coz, bg="#fb923c", **btn_style).pack(pady=10)

    def btn_anahtar(self):
        messagebox.showinfo("Bilgi", anahtar_uret())

    def btn_sifrele(self):
        yol = filedialog.askopenfilename()
        sifre = self.sifre_entry.get()
        if yol and sifre:
            messagebox.showinfo("Başarılı", hibrit_sifrele(yol, sifre))
        else:
            messagebox.showwarning("Hata", "Dosya ve şifre eksik!")

    def btn_coz(self):
        yol = filedialog.askopenfilename(filetypes=[("Hibrit Dosyalar", "*.hibrit")])
        if yol:
            try:
                messagebox.showinfo("Başarılı", hibrit_coz(yol))
            except Exception as e:
                messagebox.showerror("Hata", "Anahtar veya dosya hatalı!")

if __name__ == "__main__":
    root = tk.Tk()
    app = SifrelemeApp(root)
    root.mainloop()