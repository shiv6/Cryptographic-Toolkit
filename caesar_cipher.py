def validate_input(text, key):
    for i in range(len(text)):
        char = text[i]
        if ord(char) not in range(97, 123) and ord(char) not in range(65, 91) and ord(char) != 32:
            return False
    if type(key) is not int:
        return False
    return True


def encrypt(text, key):
    if not validate_input(text, key):
        raise Exception('Invalid input')
    result = ""
    for i in range(len(text)):
        char = text[i]
        if ord(char) == 32:
            result += char
        elif ord(char) in range(48, 54):
            result += chr((ord(char) + key - 48) % 10 + 48)
        elif char.isupper():
            result += chr((ord(char) + key - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + key - 97) % 26 + 97)
    return result


def decrypt(text, key):
    if not validate_input(text, key):
        raise Exception('Invalid input')
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char == ' ':
            result += char
        elif ord(char) in range(48, 54):
            result += chr((ord(char) - key - 48) % 10 + 48)
        elif char.isupper():
            result += chr((ord(char) - key - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) - key - 97) % 26 + 97)
    return result
