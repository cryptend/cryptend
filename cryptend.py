import base64
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import (
    Flask,
    request,
    render_template,
    redirect,
    send_from_directory,
)

base_dir = os.path.dirname(os.path.abspath(__file__))


def generate_keys() -> tuple[str, str]:
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_b = private_key.private_bytes_raw()
    public_b = public_key.public_bytes_raw()
    private_key_b64 = base64.b64encode(private_b).decode()
    public_key_b64 = base64.b64encode(public_b).decode()
    return private_key_b64, public_key_b64


def encrypt_text(plaintext: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES256.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    iv_b64 = base64.b64encode(iv).decode()
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    output = f'{iv_b64}|{ciphertext_b64}'
    return output


def decrypt_text(output: str, key: bytes) -> str:
    iv_b64 = output.split('|')[0]
    ciphertext_b64 = output.split('|')[1]
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES256.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode()


def get_utc_now() -> str:
    utc_now = datetime.now(timezone.utc)
    utc_now_iso = utc_now.isoformat(timespec='seconds')
    return utc_now_iso


def create_storage_folder() -> None:
    os.makedirs(os.path.join(base_dir, 'storage'), exist_ok=True)


def generate_chat_name() -> str:
    create_storage_folder()
    while True:
        name = os.urandom(6).hex()
        path = os.path.join(base_dir, 'storage', f'{name}.json')
        if not os.path.exists(path):
            return name


def get_chat(name: str) -> dict:
    path = os.path.join(base_dir, 'storage', f'{name}.json')
    with open(path, 'r', encoding='utf-8') as file:
        return json.load(file)


def save_chat(name: str, data: dict) -> None:
    path = os.path.join(base_dir, 'storage', f'{name}.json')
    with open(path, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=2)


app = Flask(__name__)


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon',
    )


@app.route('/')
def chats_tab():
    create_storage_folder()
    chat_files = os.listdir(os.path.join(base_dir, 'storage'))
    chats = []
    for file in chat_files:
        if file.endswith('.json'):
            name = os.path.splitext(file)[0]
            data = get_chat(name)
            chats.append((name, len(data['messages'])))
    chats = sorted(chats, key=lambda x: x[1], reverse=True)
    context = {'tab': 'chats', 'chats': chats}
    return render_template('index.html', **context)


@app.route('/1')
def generate_keys_tab():
    private_key, public_key = generate_keys()
    context = {
        'tab': 'generate_keys',
        'private_key': private_key,
        'public_key': public_key,
    }
    return render_template('index.html', **context)


@app.route('/2', methods=['GET', 'POST'])
def create_chat_tab():
    context = {'tab': 'create_chat'}
    if request.method == 'POST':
        peer_public_key = request.form['peer_public_key'].strip()
        name = generate_chat_name()
        data = {
            'peer_public_key': peer_public_key,
            'messages': [],
        }
        save_chat(name, data)
        return redirect(f'/{name}')
    return render_template('index.html', **context)


@app.route('/<name>', methods=['GET', 'POST'])
def chat_tab(name):
    context = {'tab': 'chat', 'name': name}
    if request.method == 'POST':
        data = get_chat(name)
        private_key_b64 = request.form['private_key'].strip()
        private_b = base64.b64decode(private_key_b64)
        private_key = X25519PrivateKey.from_private_bytes(private_b)
        public_b = base64.b64decode(data['peer_public_key'])
        peer_public_key = X25519PublicKey.from_public_bytes(public_b)
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'Cryptend-X25519-HKDF',
        ).derive(shared_key)
        new_message = request.form['message'].strip()
        operation = request.form['operation']
        if new_message:
            messages = []
            messages.extend(data['messages'])
            created_at = get_utc_now()
            e_created_at = encrypt_text(created_at, derived_key)
            if operation == 'encrypt':
                e_new_message = encrypt_text(new_message, derived_key)
                messages.append({
                    'text': e_new_message,
                    'created_at': e_created_at,
                    'is_my_message': True,
                })
                data['messages'] = messages
                save_chat(name, data)
                context['encrypted'] = e_new_message
            elif operation == 'decrypt':
                e_new_message = new_message
                try:
                    decrypt_text(e_new_message, derived_key)
                    messages.append({
                        'text': e_new_message,
                        'created_at': e_created_at,
                        'is_my_message': False,
                    })
                    data['messages'] = messages
                    save_chat(name, data)
                except ValueError:
                    pass
        data = get_chat(name)
        messages = []
        for msg in data['messages']:
            try:
                d_message = decrypt_text(msg['text'], derived_key)
                d_created_at = decrypt_text(msg['created_at'], derived_key)
                msg['text'] = d_message
                msg['created_at'] = d_created_at
                msg['is_encrypted'] = False
                messages.append(msg)
            except ValueError:
                msg['is_encrypted'] = True
                messages.append(msg)
        context['messages'] = messages
        if request.form.get('return_private_key'):
            context['private_key'] = private_key_b64
        return render_template('index.html', **context)
    data = get_chat(name)
    messages = []
    for msg in data['messages']:
        msg['is_encrypted'] = True
        messages.append(msg)
    context['messages'] = messages
    return render_template('index.html', **context)


if __name__ == '__main__':
    app.run()
