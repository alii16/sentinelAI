import os
from groq import Groq

# Masukkan API Key Groq Anda
client = Groq(api_key="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")

print("Sedang menghubungi Groq Cloud...")

try:
    completion = client.chat.completions.create(
        # Menggunakan model Llama 3 8B (Sangat cerdas, cepat, dan gratis)
        model="llama-3.1-8b-instant", 
        messages=[
            {"role": "system", "content": "Anda adalah asisten AI keamanan untuk proyek Sentinel AI."},
            {"role": "user", "content": "Hello! Apakah chatbot ini berfungsi dengan baik?"}
        ],
        temperature=0.7,
        max_tokens=1024,
    )

    print("\n[SUKSES] Respons dari Chatbot:")
    print(completion.choices[0].message.content)

except Exception as e:
    print(f"\n[GAGAL] Error: {e}")