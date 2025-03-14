# Telegram Cipher Bot

This project is a midterm assignment developed during university studies. It implements a Telegram bot that can encrypt and decrypt messages using various cipher techniques. The bot supports the following ciphers:

- DES Cipher
- Permutation Cipher
- Caesar Cipher
- Substitution Cipher
- Bitstream XOR Cipher

## Features

- **Interactive Conversation:** Uses a conversation handler to walk through selecting a cipher method, choosing the encryption/decryption operation, and providing necessary inputs.
- **Multiple Cipher Techniques:** Offers a variety of encryption and decryption methods to demonstrate different cryptographic concepts.
- **Educational Project:** Developed as part of a midterm assignment to showcase skills in Python programming and basic cryptography.

## Requirements

- Python 3.x
- Modules:
  - pyDes
  - python-telegram-bot

Install the dependencies using pip:

```bash
pip install pyDes python-telegram-bot
```

## Setup and Usage

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/your-repository.git
   cd your-repository
   ```

2. **Configure Your Telegram Bot Token:**

   The code example now uses a placeholder for the Telegram bot token:
   ```python
   TOKEN = "your_actual_bot_token_here"
   ```
   **Important:** Do not leave your actual token in the code when publishing to GitHub. Instead, use an environment variable to securely store the token.

   For example, modify your code as follows:
   ```python
   import os
   TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
   ```
   Before running the bot, set the environment variable in your terminal:
   ```bash
   export TELEGRAM_BOT_TOKEN="your_actual_bot_token_here"
   ```

3. **Run the Bot:**
   ```bash
   python your_script.py
   ```
   Replace `your_script.py` with the name of your main bot file.

4. **Interacting with the Bot:**
   - Start the conversation by sending the `/start` command in Telegram.
   - Follow the prompts to select a cipher method, choose whether to encrypt or decrypt, and provide the necessary key/input.
   - The bot will display the result of the operation and prompt you to select another cipher method.

## Security Note

Always ensure you do not expose sensitive information such as your Telegram bot token in your public repository. Use environment variables or a secure configuration file to manage sensitive credentials.

## License

Specify your license information here if applicable.
