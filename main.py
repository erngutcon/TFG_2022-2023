from flask import Flask, flash, redirect, render_template, request
import os
from ascon import *

app = Flask(__name__)
app.secret_key = 'proyecto_tfg_12345676'

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/demo_aead', methods=['GET', 'POST'])
def demo_aead():
    if request.method == 'POST':
        variant = request.form['variant']
        keysize = 20 if variant == "Ascon-80pq" else 16
        key = get_random_bytes(keysize)
        nonce = get_random_bytes(16)
        associateddata = request.form['associateddata'].encode()
        plaintext = request.form['plaintext'].encode()

        ciphertext = ascon_encrypt(key, nonce, associateddata, plaintext, variant)
        receivedplaintext = ascon_decrypt(key, nonce, associateddata, ciphertext, variant)

        if receivedplaintext is None:
            error = 'Decryption failed. Please check your input and try again.'
            return render_template('demo_aead.html', variant=variant, error=error)
        else:
            data = {
                'key': key.hex(),
                'nonce': nonce.hex(),
                'associateddata': associateddata.hex(),
                'plaintext': plaintext.hex(),
                'ciphertext': ciphertext[:-16].hex(),
                'tag': ciphertext[-16:].hex(),
                'received': receivedplaintext.hex(),
            }
            return render_template('demo_aead.html', variant=variant, result=data)
    else:
        return render_template('demo_aead.html', result={})




@app.route('/demo_hash', methods=['GET', 'POST'])
def demo_hash():
    if request.method == 'POST':
        variant = request.form['variant']
        hashlength = int(request.form['hashlength'])
        message = bytes(request.form['message'], 'utf-8')

        if variant in ['Ascon-Hash', 'Ascon-Hasha'] and hashlength != 32:
            flash('Invalid hash length for the selected variant')
            return redirect(request.url)

        tag = ascon_hash(message, variant, hashlength)

        data = {
            'message': message.hex(),
            'tag': tag.hex(),
        }
        return render_template('demo_hash.html', variant=variant, data=data)
    else:
        return render_template('demo_hash.html')
        

@app.route('/demo_mac', methods=['GET', 'POST'])
def demo_mac():
    if request.method == 'POST':
        variant = request.form['variant']
        keysize = 16
        key = get_random_bytes(keysize)
        message = bytes(request.form['message'], 'utf-8')
        tag = ascon_mac(key, message, variant)

        data = {
            'key': key.hex(),
            'message': message.hex(),
            'tag': tag.hex(),
        }
        return render_template('demo_mac.html', variant=variant, data=data)
    else:
        return render_template('demo_mac.html', variant="Ascon-Mac")


if __name__ == '__main__':
    app.run()

