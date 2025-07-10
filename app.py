from flask import Flask, render_template, request
import random
import base64

app = Flask(__name__)

def run_bb84_simulation(message):
    n = 100
    alice_bits = [random.randint(0, 1) for _ in range(n)]
    alice_bases = [random.choice(['X', 'Z']) for _ in range(n)]
    bob_bases = [random.choice(['X', 'Z']) for _ in range(n)]
    eve_present = random.random() < 0.7

    bob_results = []
    eve_results = []

    for i in range(n):
        bit = alice_bits[i]
        base = alice_bases[i]

        if eve_present:
            eve_base = random.choice(['X', 'Z'])
            eve_bit = bit if base == eve_base else random.randint(0, 1)
            eve_results.append(eve_bit)

            final_bit = eve_bit if eve_base == bob_bases[i] else random.randint(0, 1)
        else:
            final_bit = bit if base == bob_bases[i] else random.randint(0, 1)

        bob_results.append(final_bit)

    matching_indices = [i for i in range(n) if alice_bases[i] == bob_bases[i]]
    alice_key = [alice_bits[i] for i in matching_indices]
    bob_key = [bob_results[i] for i in matching_indices]

    error_count = sum(1 for i in range(len(alice_key)) if alice_key[i] != bob_key[i])
    error_rate = (error_count / len(alice_key)) * 100 if alice_key else 0

    key_length = len(alice_key)
    mismatch_log = [i for i in matching_indices if alice_bits[i] != bob_results[i]]

    encrypted_base64 = ""
    decrypted_message = ""

    if message:
        byte_msg = message.encode("utf-8")
        bin_msg = ''.join(format(byte, '08b') for byte in byte_msg)
        key_stream = (alice_key * ((len(bin_msg) // len(alice_key)) + 1))[:len(bin_msg)]
        xor_result = ''.join(str(int(bit) ^ k) for bit, k in zip(bin_msg, key_stream))
        xor_bytes = bytes(int(xor_result[i:i+8], 2) for i in range(0, len(xor_result), 8))

        try:
            encrypted_base64 = base64.b64encode(xor_bytes).decode('utf-8')
            decrypted_bytes = base64.b64decode(encrypted_base64.encode('utf-8'))
            decrypted_bin = ''.join(format(byte, '08b') for byte in decrypted_bytes)
            key_stream = (alice_key * ((len(decrypted_bin) // len(alice_key)) + 1))[:len(decrypted_bin)]
            original_bin = ''.join(str(int(bit) ^ k) for bit, k in zip(decrypted_bin, key_stream))
            decrypted_message = ''.join(chr(int(original_bin[i:i+8], 2)) for i in range(0, len(original_bin), 8))
        except Exception as e:
            decrypted_message = "⚠️ Decryption failed (possible data corruption)"

    return {
        'error_rate': round(error_rate, 2),
        'key_length': key_length,
        'decrypted_message': decrypted_message,
        'eavesdrop_detected': error_rate > 20,
        'mismatch_log': mismatch_log,
        'encrypted_base64': encrypted_base64
    }

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        message = request.form.get('message', '')
        result = run_bb84_simulation(message)
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
