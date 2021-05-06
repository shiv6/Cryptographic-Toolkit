from flask import Flask, request
import json
import caesar_cipher
import affine_cipher
import vigenere_cipher
import rail_fence_cipher
import columnar_cipher
import modern_cipher

app = Flask(__name__)

@app.route('/caesar_cipher', methods=['POST'])
def caesar():
    '''
    :input:
        {
            'process_type': 'encryption'\'decryption',
            'key': <integer value>,
            'text': <raw/encrypted message>
        }
    :return:
        {
            'status': 'success'/'failure',
            'msg': NA/<error message>,
            'text': NA/<encrypted/decrypted message>
    '''
    try:
        req_body = request.get_json()
        process_type = req_body.get('process_type')
        if process_type == 'encryption':
            cipher = caesar_cipher.encrypt(req_body.get('text'), int(req_body.get('key')))
            return {
                'status': 'success',
                'text': cipher
            }
        elif process_type == 'decryption':
            cipher = caesar_cipher.decrypt(req_body.get('text'), int(req_body.get('key')))
            return {
                'status': 'success',
                'text': cipher
            }
        else:
            return {
                'status': 'failure',
                'msg': 'invalid process type! Process type can only be encryption or decryption for caesar cipher.'
            }
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'Process failed! Reason: {e}'
        }

@app.route('/affine_cipher', methods=['POST'])
def affine():
    '''
    :input:
        {
            'process_type': 'encryption'\'decryption',
            'key': [<integer value>, <integer_value],
            'text': <raw/encrypted message>
        }
    :return:
        {
            'status': 'success'/'failure',
            'msg': NA/<error message>,
            'text': NA/<encrypted/decrypted message>
    '''
    try:
        req_body = request.get_json()
        process_type = req_body.get('process_type')
        if process_type == 'encryption':
            cipher = affine_cipher.encrypt(req_body.get('text'), req_body.get('key'))
            return {
                'status': 'success',
                'text': cipher
            }
        elif process_type == 'decryption':
            cipher = affine_cipher.decrypt(req_body.get('text'), req_body.get('key'))
            return {
                'status': 'success',
                'text': cipher
            }
        else:
            return {
                'status': 'failure',
                'msg': 'invalid process type! Process type can only be encryption or decryption for Affine cipher.'
            }
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'Process failed! Reason: {e}'
        }


@app.route('/vigenere_cipher', methods=['POST'])
def vignere():
    '''
    :input:
        {
            'process_type': 'encryption'\'decryption',
            'key': <string>,
            'text': <raw/encrypted message>
        }
    :return:
        {
            'status': 'success'/'failure',
            'msg': NA/<error message>,
            'text': NA/<encrypted/decrypted message>
    '''
    try:
        req_body = request.get_json()
        process_type = req_body.get('process_type')
        if process_type == 'encryption':
            cipher = vigenere_cipher.encrypt(req_body.get('text'), req_body.get('key'))
            return {
                'status': 'success',
                'text': cipher
            }
        elif process_type == 'decryption':
            cipher = vigenere_cipher.decrypt(req_body.get('text'), req_body.get('key'))
            return {
                'status': 'success',
                'text': cipher
            }
        else:
            return {
                'status': 'failure',
                'msg': 'invalid process type! Process type can only be encryption or decryption for Vigenere cipher.'
            }
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'Process failed! Reason: {e}'
        }

@app.route('/rail_fence_cipher', methods=['POST'])
def rail_fence():
    '''
    :input:
        {
            'process_type': 'encryption'\'decryption',
            'key': <integer>,
            'text': <raw/encrypted message>
        }
    :return:
        {
            'status': 'success'/'failure',
            'msg': NA/<error message>,
            'text': NA/<encrypted/decrypted message>
    '''
    try:
        req_body = request.get_json()
        process_type = req_body.get('process_type')
        if process_type == 'encryption':
            cipher = rail_fence_cipher.encrypt(req_body.get('text'), int(req_body.get('key')))
            return {
                'status': 'success',
                'text': cipher
            }
        elif process_type == 'decryption':
            cipher = rail_fence_cipher.decrypt(req_body.get('text'), int(req_body.get('key')))
            return {
                'status': 'success',
                'text': cipher
            }
        else:
            return {
                'status': 'failure',
                'msg': 'invalid process type! Process type can only be encryption or decryption for Rail fence cipher.'
            }
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'Process failed! Reason: {e}'
        }

@app.route('/columnar_cipher', methods=['POST'])
def columnar():
    '''
    :input:
        {
            'process_type': 'encryption'\'decryption',
            'key': <string>,
            'text': <raw/encrypted message>
        }
    :return:
        {
            'status': 'success'/'failure',
            'msg': NA/<error message>,
            'text': NA/<encrypted/decrypted message>
    '''
    try:
        req_body = request.get_json()
        process_type = req_body.get('process_type')
        if process_type == 'encryption':
            cipher = columnar_cipher.encrypt(req_body.get('text'), req_body.get('key'))
            return {
                'status': 'success',
                'text': cipher
            }
        elif process_type == 'decryption':
            cipher = columnar_cipher.decrypt(req_body.get('text'), req_body.get('key'))
            return {
                'status': 'success',
                'text': cipher
            }
        else:
            return {
                'status': 'failure',
                'msg': 'invalid process type! Process type can only be encryption or decryption for Columnar cipher.'
            }
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'Process failed! Reason: {e}'
        }

@app.route('/AES', methods=['POST'])
def AES():
    '''
    :input:
        {
            'process_type': 'encryption'\'decryption',
            'key': <string>,
            'text': <raw/encrypted message>
        }
    :return:
        {
            'status': 'success'/'failure',
            'msg': NA/<error message>,
            'text': NA/<encrypted/decrypted message>
    '''
    try:
        req_body = request.get_json()
        process_type = req_body.get('process_type')
        if process_type == 'encryption':
            cipher = modern_cipher.AESCipher(req_body.get('key')).encrypt(req_body.get('text'))
            return {
                'status': 'success',
                'text': cipher.decode()
            }
        elif process_type == 'decryption':
            cipher = modern_cipher.AESCipher(req_body.get('key')).decrypt(req_body.get('text'))
            return {
                'status': 'success',
                'text': cipher
            }
        else:
            return {
                'status': 'failure',
                'msg': 'invalid process type! Process type can only be encryption or decryption for AES cipher.'
            }
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'Process failed! Reason: {e}'
        }

@app.route('/DES', methods=['POST'])
def DES():
    '''
    :input:
        {
            'process_type': 'encryption'\'decryption',
            'key': <string>,
            'text': <raw/encrypted message>
        }
    :return:
        {
            'status': 'success'/'failure',
            'msg': NA/<error message>,
            'text': NA/<encrypted/decrypted message>
    '''
    try:
        req_body = request.get_json()
        process_type = req_body.get('process_type')
        if process_type == 'encryption':
            cipher = modern_cipher.DESCipher(req_body.get('key')).encrypt(req_body.get('text'))
            return {
                'status': 'success',
                'text': cipher.decode()
            }
        elif process_type == 'decryption':
            cipher = modern_cipher.DESCipher(req_body.get('key')).decrypt(req_body.get('text'))
            return {
                'status': 'success',
                'text': cipher
            }
        else:
            return {
                'status': 'failure',
                'msg': 'invalid process type! Process type can only be encryption or decryption for DES cipher.'
            }
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'Process failed! Reason: {e}'
        }

@app.route('/Blowfish', methods=['POST'])
def Blowfish():
    '''
    :input:
        {
            'process_type': 'encryption'\'decryption',
            'key': <string>,
            'text': <raw/encrypted message>
        }
    :return:
        {
            'status': 'success'/'failure',
            'msg': NA/<error message>,
            'text': NA/<encrypted/decrypted message>
    '''
    try:
        req_body = request.get_json()
        process_type = req_body.get('process_type')
        if process_type == 'encryption':
            cipher = modern_cipher.BlowfishCipher(req_body.get('key')).encrypt(req_body.get('text'))
            return {
                'status': 'success',
                'text': cipher.decode()
            }
        elif process_type == 'decryption':
            cipher = modern_cipher.BlowfishCipher(req_body.get('key')).decrypt(req_body.get('text'))
            return {
                'status': 'success',
                'text': cipher
            }
        else:
            return {
                'status': 'failure',
                'msg': 'invalid process type! Process type can only be encryption or decryption for Blowfish cipher.'
            }
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'Process failed! Reason: {e}'
        }

@app.route('/ARC4', methods=['POST'])
def ARC4():
    '''
    :input:
        {
            'process_type': 'encryption'\'decryption',
            'key': <string>,
            'text': <raw/encrypted message>
        }
    :return:
        {
            'status': 'success'/'failure',
            'msg': NA/<error message>,
            'text': NA/<encrypted/decrypted message>
    '''
    try:
        req_body = request.get_json()
        process_type = req_body.get('process_type')
        if process_type == 'encryption':
            cipher = modern_cipher.ARC4Cipher(req_body.get('key')).encrypt(req_body.get('text'))
            return {
                'status': 'success',
                'text': cipher.decode()
            }
        elif process_type == 'decryption':
            cipher = modern_cipher.ARC4Cipher(req_body.get('key')).decrypt(bytes(req_body.get('text'), 'utf-8'))
            return {
                'status': 'success',
                'text': cipher
            }
        else:
            return {
                'status': 'failure',
                'msg': 'invalid process type! Process type can only be encryption or decryption for ceasar cipher.'
            }
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'Process failed! Reason: {e}'
        }
@app.route('/RSA/generate_key', methods=['GET'])
def RSA_key():
    try:
        pub, priv = modern_cipher.RSA_OAEP().generate_key()
        return{
            'status': 'success',
            'public-key': pub,
            'private-key': priv
        }
    except Exception as e:
        return{
            'status': 'failure',
            'msg': f'key generation failed! Reason: {e}'
        }

@app.route('/RSA', methods=['POST'])
def RSA():
    '''
    :input:
        {
            'process_type': 'encryption'\'decryption',
            'key': <string>,
            'text': <raw/encrypted message>
        }
    :return:
        {
            'status': 'success'/'failure',
            'msg': NA/<error message>,
            'text': NA/<encrypted/decrypted message>
    '''
    try:
        req_body = request.get_json()
        process_type = req_body.get('process_type')
        if process_type == 'encryption':
            cipher = modern_cipher.RSA_OAEP().encrypt(req_body.get('text'), req_body.get('key'))
            return {
                'status': 'success',
                'text': cipher.decode()
            }
        elif process_type == 'decryption':
            cipher = modern_cipher.RSA_OAEP().decrypt(bytes(req_body.get('text'), 'utf-8'), req_body.get('key'))
            return {
                'status': 'success',
                'text': cipher.decode()
            }
        else:
            return {
                'status': 'failure',
                'msg': 'invalid process type! Process type can only be encryption or decryption for ceasar cipher.'
            }
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'Process failed! Reason: {e}'
        }


@app.route('/DSA/generate_key', methods=['GET'])
def DSA_key():
    try:
        pub, priv = modern_cipher.DSA_Signature().generate_key()
        return{
            'status': 'success',
            'public-key': pub,
            'private-key': priv
        }
    except Exception as e:
        return{
            'status': 'failure',
            'msg': f'key generation failed! Reason: {e}'
        }

@app.route('/DSA', methods=['POST'])
def DSA():
    '''
    :input:
        {
            'process_type': 'sign'\'verify',
            'key': <string>,
            'text': <raw message>,
            'signature': NA/<signature>
        }
    :return:
        {
            'status': 'success'/'failure',
            'msg': NA/<error message>,
            'text': NA/<signature/is-verified>
    '''
    try:
        req_body = request.get_json()
        process_type = req_body.get('process_type')
        if process_type == 'sign':
            cipher = modern_cipher.DSA_Signature().sign_message(req_body.get('text'), req_body.get('key'))
            return {
                'status': 'success',
                'text': cipher.decode()
            }
        elif process_type == 'verify':
            result = modern_cipher.DSA_Signature().varify_message(req_body.get('text'), bytes(req_body.get('signature'), 'utf-8'), req_body.get('key'))
            value = 'Verified' if result else 'Not Verified'
            return {
                'status': 'success',
                'text': value
            }
        else:
            return {
                'status': 'failure',
                'msg': 'invalid process type! Process type can only be encryption or decryption for ceasar cipher.'
            }
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'Process failed! Reason: {e}'
        }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)