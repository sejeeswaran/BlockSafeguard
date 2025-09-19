# BlockSafeguard
# 🚀 BlockSafeguard - Enterprise DDoS Protection System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1+-red.svg)](https://flask.palletsprojects.com/)

BlockSafeguard is a comprehensive cybersecurity solution that provides real-time DDoS attack detection and mitigation using advanced algorithms and blockchain technology for immutable audit trails.

## ✨ Key Features

- 🔍 **Real-time DDoS Detection**: Advanced algorithms detect various attack patterns
- 🚫 **Automated IP Blocking**: Instant blocking at network and application levels
- ⛓️ **Blockchain Integration**: Immutable audit trails for all security actions
- ☁️ **AWS NACL Integration**: Network-level protection using AWS security groups
- 🔐 **Firebase Authentication**: Secure user management with role-based access
- 📊 **Web Dashboard**: Intuitive interface for IP management and monitoring
- 🛡️ **Password Protection**: Additional security for sensitive operations
- 📝 **Comprehensive Logging**: Detailed logs for analysis and compliance

## 🛠️ Technologies Used

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, Bootstrap, JavaScript
- **Blockchain**: Solidity, Web3.py
- **Database**: Firebase Firestore
- **Cloud**: AWS (EC2, NACL)
- **Authentication**: Firebase Auth
- **Deployment**: Gunicorn, Docker

## 📋 Prerequisites

- Python 3.8 or higher
- Node.js (for some utilities)
- AWS Account with EC2 access
- Firebase Project
- Git

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/sejeeswaran/BlockSafeguard.git
cd BlockSafeguard
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Firebase Setup
1. Create a Firebase project at https://console.firebase.google.com/
2. Enable Authentication and Firestore
3. Download the service account key JSON file
4. Place it in the project root as `blocksafeguard-5f3df-firebase-adminsdk-fbsvc-d590732ddd.json`

### 4. AWS Configuration
1. Set up AWS credentials
2. Configure EC2 instance and security groups
3. Update AWS settings in `aws_blocker.py`

### 5. Blockchain Setup
1. Deploy the smart contract to your preferred network
2. Update contract address in configuration files
3. Set up Web3 provider

## ⚙️ Configuration

### Environment Variables
Create a `.env` file in the root directory:
```env
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
FIREBASE_API_KEY=your-firebase-api-key
AWS_REGION=us-east-1
BLOCKCHAIN_RPC_URL=https://your-rpc-url
```

### Firebase Web API Key
Update `app.py` with your Firebase Web API Key:
```python
api_key = "YOUR_FIREBASE_WEB_API_KEY"
```

## 🎯 Usage

### Starting the Application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

### Web Interface
- **Dashboard**: Monitor blocked/unblocked IPs
- **Login/Signup**: User authentication
- **Status Page**: Real-time security status
- **IP Management**: Block/unblock IPs with password verification

### API Endpoints

#### Authentication
- `GET /` - Home page
- `GET/POST /login` - User login
- `GET/POST /signup` - User registration
- `GET /logout` - User logout

#### IP Management
- `GET /status` - Security dashboard
- `POST /block/<ip>` - Block an IP address
- `POST /unblock/<ip>` - Unblock an IP address

#### API Endpoints
- `GET /api/status/<api_key>` - Get protection status
- `POST /api/check` - Check if IP should be blocked
- `POST /api/unblock/<api_key>/<ip>` - Unblock IP via API

## 🔧 Development

### Running Tests
```bash
python -m pytest
```

### Code Structure
```
BSGuard/
├── app.py                 # Main Flask application
├── firebase_client.py     # Firebase integration
├── aws_blocker.py         # AWS NACL management
├── blockchain_logger.py   # Blockchain interactions
├── BlockSafeguard.sol     # Smart contract
├── templates/             # HTML templates
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   └── status.html
├── static/               # CSS, JS, images
├── requirements.txt      # Python dependencies
├── .gitignore           # Git ignore rules
└── README.md            # This file
```

## 🚀 Deployment

### Local Development
```bash
python app.py
```

### Production Deployment
```bash
gunicorn --bind 0.0.0.0:8000 app:app
```

### Docker Deployment
```bash
docker build -t blocksafeguard .
docker run -p 5000:5000 blocksafeguard
```

## 🔒 Security Features

- **Password Verification**: All sensitive operations require password confirmation
- **Role-based Access**: Different permission levels for users
- **Immutable Logs**: Blockchain ensures audit trail integrity
- **Network Protection**: Multi-layer blocking (application + network)
- **Real-time Monitoring**: Continuous threat detection

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

For support and questions:
- 📧 Email: blocksafeguard@gmail.com
- 📖 Documentation: [DEPLOYMENT_README.md](DEPLOYMENT_README.md)
- 🐛 Issues: [GitHub Issues](https://github.com/sejeeswaran/BlockSafeguard/issues)

## 🙏 Acknowledgments

- Flask framework for the web application
- AWS for cloud infrastructure
- Firebase for authentication and database
- Web3.py for blockchain integration
- Bootstrap for UI components

---

**BlockSafeguard** - Protecting your digital assets with cutting-edge security technology! 🛡️✨
