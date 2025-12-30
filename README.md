echo "# 🚨 Docker Honeypot System" > README.md
echo "" >> README.md
echo "A real honeypot system that detects and logs SSH brute-force attacks using Docker containers." >> README.md
echo "" >> README.md
echo "## 📋 Features" >> README.md
echo "- ✅ **Real SSH Honeypot** - Detects actual attack attempts" >> README.md
echo "- ✅ **Real-time Dashboard** - Shows attacks as they happen" >> README.md
echo "- ✅ **JSON Logging** - All attacks saved in structured format" >> README.md
echo "- ✅ **Statistics** - Attack counts, unique IPs, trends" >> README.md
echo "- ✅ **Bait Files** - Fake credentials to attract attackers" >> README.md
echo "" >> README.md
echo "## 🚀 Quick Start" >> README.md
echo "" >> README.md
echo "### 1. Install Dependencies" >> README.md
echo '`bash' >> README.md
echo "pip install docker" >> README.md
echo '`' >> README.md
echo "" >> README.md
echo "### 2. Start All Honeypots" >> README.md
echo '`bash' >> README.md
echo "python main.py --all" >> README.md
echo '`' >> README.md
echo "" >> README.md
echo "### 3. View Real-time Dashboard" >> README.md
echo '`bash' >> README.md
echo "python main.py --dashboard" >> README.md
echo '`' >> README.md
echo "" >> README.md
echo "## 🔧 Manual Testing" >> README.md
echo "" >> README.md
echo "### Test SSH Honeypot (use WRONG password):" >> README.md
echo '`bash' >> README.md
echo "ssh admin@localhost -p 2222" >> README.md
echo "# Password: password123 (use wrong password like 'wrong123')" >> README.md
echo '`' >> README.md
echo "" >> README.md
echo "### Test Web Honeypot:" >> README.md
echo '`bash' >> README.md
echo "curl http://localhost:8080" >> README.md
echo "curl http://localhost:8080/wp-login.php" >> README.md
echo '`' >> README.md
echo "" >> README.md
echo "## 📊 Commands" >> README.md
echo "" >> README.md
echo "| Command | Description |" >> README.md
echo "|---------|-------------|" >> README.md
echo "| `python main.py --all` | Start all honeypots |" >> README.md
echo "| `python main.py --ssh` | Start only SSH honeypot |" >> README.md
echo "| `python main.py --web` | Start only WordPress honeypot |" >> README.md
echo "| `python main.py --dashboard` | Show real-time attack dashboard |" >> README.md
echo "| `python main.py --monitor` | Start background attack monitoring |" >> README.md
echo "| `python main.py --report` | Generate attack report |" >> README.md
echo "" >> README.md
echo "## 📁 Project Structure" >> README.md
echo "" >> README.md
echo "`" >> README.md
echo "honeypot/" >> README.md
echo "├── main.py              # Main controller" >> README.md
echo "├── docker_manager.py    # Docker container management" >> README.md
echo "├── attack_monitor.py    # Attack detection and logging" >> README.md
echo "├── bait_creator.py      # Create fake credentials/files" >> README.md
echo "├── containers/          # Docker configurations" >> README.md
echo "│   ├── Dockerfile.ssh   # SSH honeypot image" >> README.md
echo "│   └── ssh_logger.py    # SSH attack logger" >> README.md
echo "├── logs/                # Attack logs (auto-created)" >> README.md
echo "│   ├── all_attacks.json # All attacks in JSON format" >> README.md
echo "│   ├── ssh_attacks.json # SSH-specific attacks" >> README.md
echo "│   ├── web_attacks.json # Web-specific attacks" >> README.md
echo "│   └── final_report.json# Generated reports" >> README.md
echo "└── bait_files/          # Fake files to attract attackers" >> README.md
echo "`" >> README.md
echo "" >> README.md
echo "## 🐳 Docker Containers" >> README.md
echo "" >> README.md
echo "| Container | Port | Description |" >> README.md
echo "|-----------|------|-------------|" >> README.md
echo "| `real-ssh-honeypot` | 2222 | SSH server with logging |" >> README.md
echo "| `real-wordpress-honeypot` | 8080 | WordPress site |" >> README.md
echo "| `real-mysql-honeypot` | 3306 | MySQL database |" >> README.md
echo "" >> README.md
echo "## 📈 What It Detects" >> README.md
echo "" >> README.md
echo "### SSH Attacks:" >> README.md
echo "- Failed password attempts" >> README.md
echo "- Invalid user attempts" >> README.md
echo "- Connection attempts" >> README.md
echo "" >> README.md
echo "### Web Attacks:" >> README.md
echo "- WordPress login attempts" >> README.md
echo "- Suspicious paths (wp-admin, config files)" >> README.md
echo "- Error responses" >> README.md
echo "" >> README.md
echo "## ⚠️ Important Notes" >> README.md
echo "" >> README.md
echo "1. **This is a REAL honeypot** - it will log actual attack attempts" >> README.md
echo "2. **Use on isolated network** - exposing to internet will attract real attackers" >> README.md
echo "3. **Test with wrong passwords** - use 'wrong123' not the real password" >> README.md
echo "4. **Attacks may appear automatically** - background scans are normal" >> README.md
echo "" >> README.md
echo "## 🛠️ Troubleshooting" >> README.md
echo "" >> README.md
echo "**Issue:** No attacks detected" >> README.md
echo "**Solution:** Test manually: \`ssh admin@localhost -p 2222\` (use wrong password)" >> README.md
echo "" >> README.md
echo "**Issue:** Docker not available" >> README.md
echo "**Solution:** Install Docker Desktop and run: \`pip install docker\`" >> README.md
echo "" >> README.md
echo "**Issue:** Dashboard shows 0 attacks" >> README.md
echo "**Solution:** Attacks appear in real-time. Wait or trigger test attack." >> README.md
echo "" >> README.md
echo "## 📄 License" >> README.md
echo "Educational project for security research" >> README.md
