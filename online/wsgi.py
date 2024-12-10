from run import app
from dotenv import load_dotenv
import os


application = app

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    application.run(host='0.0.0', port=port)
