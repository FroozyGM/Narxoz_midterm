import pyDes
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ConversationHandler,
    ContextTypes,
    filters
)

METHOD, OPERATION, TEXT, KEY = range(4)

TOKEN = "your_actual_bot_token_here"
DES_KEY = "8bytekey" 
DES_OBJ = pyDes.des(DES_KEY, pyDes.ECB, padmode=pyDes.PAD_PKCS5)

def permutation_cipher(plaintext: str, key: list) -> str:
    block_size = len(key)
    ciphertext = ""
    padding_length = (block_size - len(plaintext) % block_size) % block_size
    plaintext += " " * padding_length
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        permuted_block = ""
        for j in range(len(key)):
            permuted_block += block[key.index(j)]
        ciphertext += permuted_block
    return ciphertext

def permutation_decipher(ciphertext: str, key: list) -> str:
    block_size = len(key)
    plaintext = ""
    padding_length = (block_size - len(ciphertext) % block_size) % block_size
    ciphertext += " " * padding_length
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        permuted_block = ""
        for j in range(len(key)):
            permuted_block += block[key[j]]
        plaintext += permuted_block
    return plaintext.rstrip()

def word_to_indexes(word: str) -> list:
    indexes = [ord(char.upper()) - ord('A') for char in word if char.isalpha()]
    unique_sorted_indexes = sorted(set(indexes))
    permutation_key = [unique_sorted_indexes.index(i) for i in indexes]
    return permutation_key

def shift_encrypt(plaintext: str, shift: int) -> str:
    result = ""
    for ch in plaintext:
        if (ch.isupper()):
            result += chr((ord(ch) + shift - 65) % 26 + 65)
        elif (ch.islower()):
            result += chr((ord(ch) + shift - 97) % 26 + 97)
        else:
            result += ch
    return result

def shift_decrypt(ciphertext: str, shift: int) -> str:
    return shift_encrypt(ciphertext, -shift)

def substitution_encrypt(plaintext: str, key: str) -> str:
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    key = key.lower()
    mapping = {alphabet[i]: key[i] for i in range(26)}
    result = ""
    for ch in plaintext:
        if ch.isalpha():
            if ch.islower():
                result += mapping.get(ch, ch)
            else:
                result += mapping.get(ch.lower(), ch).upper()
        else:
            result += ch
    return result

def substitution_decrypt(ciphertext: str, key: str) -> str:
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    key = key.lower()
    mapping = {key[i]: alphabet[i] for i in range(26)}
    result = ""
    for ch in ciphertext:
        if ch.isalpha():
            if ch.islower():
                result += mapping.get(ch, ch)
            else:
                result += mapping.get(ch.lower(), ch).upper()
        else:
            result += ch
    return result

def text_to_bitstream(text):
    return ''.join(format(ord(char), '08b') for char in text)

def bitstream_to_text(bitstream):
    chars = [bitstream[i:i+8] for i in range(0, len(bitstream), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

def xor_bitstreams(bitstream, key):
    return ''.join(str(int(b) ^ int(k)) for b, k in zip(bitstream, key))

def encrypt_decrypt(text, key):
    bitstream = text_to_bitstream(text)
    while len(bitstream) % 64 != 0:
        bitstream += '0'
    key_bitstream = text_to_bitstream(key)
    key_bitstream = key_bitstream[:64].ljust(64, '0') 
    blocks = [bitstream[i:i+64] for i in range(0, len(bitstream), 64)]
    encrypted_blocks = [xor_bitstreams(block, key_bitstream) for block in blocks]
    encrypted_bitstream = ''.join(encrypted_blocks)
    return encrypted_bitstream

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text(
        "Welcome to Crypto Bot!\nChoose cipher method:",
        reply_markup=ReplyKeyboardMarkup([
            ["DES Cipher"],
            ["Permutation Cipher"], 
            ["Caesar Cipher"], 
            ["Substitution Cipher"],
            ["Bitstream XOR Cipher"]
        ], one_time_keyboard=True)
    )
    return METHOD

async def method_choice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data["method"] = update.message.text
    
    if context.user_data["method"] == "DES Cipher":
        await update.message.reply_text(
            "What would you like to do?",
            reply_markup=ReplyKeyboardMarkup([
                ["Encrypt", "Decrypt"]
            ], one_time_keyboard=True)
        )
    else:
        await update.message.reply_text(
            "Encrypt or Decrypt?",
            reply_markup=ReplyKeyboardMarkup([
                ["Encrypt", "Decrypt"]
            ], one_time_keyboard=True)
        )
    return OPERATION

async def operation_choice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data["operation"] = update.message.text
    
    if context.user_data["operation"] == "Encrypt":
        await update.message.reply_text("Enter text to encrypt:")
    else:
        method = context.user_data["method"]
        if method == "DES Cipher":
            await update.message.reply_text("Enter hex data to decrypt:")
        else:
            await update.message.reply_text("Enter text to decrypt:")
    return TEXT

async def process_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data["text"] = update.message.text
    method = context.user_data["method"]
    
    if method == "DES Cipher":
        return await process_des(update, context)
    elif method == "Caesar Cipher":
        await update.message.reply_text("Enter shift value (a number):")
        return KEY
    elif method == "Substitution Cipher":
        await update.message.reply_text("Enter substitution key (26 unique letters):")
        return KEY
    elif method == "Bitstream XOR Cipher":
        await update.message.reply_text("Enter key (8-char key):")
        return KEY
    else:  
        await update.message.reply_text("Enter key word:")
        return KEY

async def process_des(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    operation = context.user_data["operation"]
    text = context.user_data["text"]
    
    try:
        if operation == "Encrypt":
            cipher_hex = DES_OBJ.encrypt(text).hex()
            await update.message.reply_text(f"Encrypted data:\n{cipher_hex}")
        else:  
            try:
                decrypted = DES_OBJ.decrypt(bytes.fromhex(text)).decode()
                await update.message.reply_text(f"Decrypted text:\n{decrypted}")
            except Exception:
                await update.message.reply_text("Decryption failed. Make sure you entered valid hex data.")
        
        await update.message.reply_text(
            "Choose cipher method:",
            reply_markup=ReplyKeyboardMarkup([
                ["DES Cipher"],
                ["Permutation Cipher"], 
                ["Caesar Cipher"], 
                ["Substitution Cipher"],
                ["Bitstream XOR Cipher"]
            ], one_time_keyboard=True)
        )
        return METHOD
    except Exception as e:
        await update.message.reply_text(f"Error: {str(e)}")
        return ConversationHandler.END

async def process_key(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        user_data = context.user_data
        method = user_data["method"]
        operation = user_data["operation"]
        input_text = user_data["text"]
        key_input = update.message.text
        
        if method == "Permutation Cipher":
            key_list = word_to_indexes(key_input)
            if operation == "Encrypt":
                result = permutation_cipher(input_text, key_list)
            else:
                result = permutation_decipher(input_text, key_list)
                
        elif method == "Caesar Cipher":
            try:
                shift = int(key_input)
                if operation == "Encrypt":
                    result = shift_encrypt(input_text, shift)
                else:
                    result = shift_decrypt(input_text, shift)
            except ValueError:
                await update.message.reply_text("Error: Shift must be a number!")
                return ConversationHandler.END
                
        elif method == "Substitution Cipher":
            if len(set(key_input.lower().replace(" ", ""))) != 26 or not all(c.isalpha() for c in key_input.replace(" ", "")):
                await update.message.reply_text("Error: Key must contain 26 unique letters!")
                return ConversationHandler.END
                
            if operation == "Encrypt":
                result = substitution_encrypt(input_text, key_input)
            else:
                result = substitution_decrypt(input_text, key_input)
        
        elif method == "Bitstream XOR Cipher":
            if len(key_input) != 8:
                await update.message.reply_text("Error: Key must be exactly 8 characters long!")
                return KEY
            if operation == "Encrypt":
                result = "Cipher Bitstream:\n" + encrypt_decrypt(input_text, key_input)
            else:
                try:
                    decrypted_bitstream = encrypt_decrypt(bitstream_to_text(input_text), key_input)
                    result = "Decrypted Text:\n" + bitstream_to_text(decrypted_bitstream)
                except Exception:
                    result = "Decryption error. Check input format."
                
        await update.message.reply_text(f"Result:\n{result}")
        
        await update.message.reply_text(
            "Choose cipher method:",
            reply_markup=ReplyKeyboardMarkup([
                ["DES Cipher"],
                ["Permutation Cipher"], 
                ["Caesar Cipher"], 
                ["Substitution Cipher"],
                ["Bitstream XOR Cipher"]
            ], one_time_keyboard=True)
        )
        return METHOD
        
    except Exception as e:
        await update.message.reply_text(f"Error: {str(e)}")
    return ConversationHandler.END

def main():
    app = Application.builder().token(TOKEN).build()
    
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            METHOD: [MessageHandler(filters.TEXT & ~filters.COMMAND, method_choice)],
            OPERATION: [MessageHandler(filters.TEXT & ~filters.COMMAND, operation_choice)],
            TEXT: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_text)],
            KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_key)]
        },
        fallbacks=[]
    )
    
    app.add_handler(conv_handler)
    app.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()