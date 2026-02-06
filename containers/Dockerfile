FROM ubuntu:22.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openssh-server sudo python3 bsdutils net-tools vim wget curl tzdata \
    && rm -rf /var/lib/apt/lists/*

# Set Algeria timezone (Africa/Algiers)
RUN ln -fs /usr/share/zoneinfo/Africa/Algiers /etc/localtime
RUN echo "Africa/Algiers" > /etc/timezone

RUN useradd -m -s /bin/bash admin && \
    echo "admin:password123" | chpasswd && \
    usermod -aG sudo admin

RUN echo "root:toor" | chpasswd && \
    usermod -s /bin/bash root

RUN mkdir /var/run/sshd
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
RUN echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
RUN echo "AllowUsers admin root" >> /etc/ssh/sshd_config
RUN echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
RUN echo "MaxAuthTries 100" >> /etc/ssh/sshd_config
RUN echo "PrintMotd no" >> /etc/ssh/sshd_config
RUN ln -sf /proc/1/fd/1 /var/log/auth.log
RUN ln -sf /proc/1/fd/2 /var/log/auth.err

RUN mkdir -p /var/log/ssh_sessions && chmod 777 /var/log/ssh_sessions

RUN mkdir -p /var/log/ssh_sessions && chmod 777 /var/log/ssh_sessions

# CREATE THE LOG FILE so bash can write to it
RUN touch /var/log/ssh_sessions/commands.log && chmod 666 /var/log/ssh_sessions/commands.log

RUN echo 'export HISTSIZE=10000' > /etc/bash.bashrc
RUN echo 'export HISTFILESIZE=20000' >> /etc/bash.bashrc
RUN echo 'export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "' >> /etc/bash.bashrc
RUN echo 'shopt -s histappend' >> /etc/bash.bashrc
RUN echo 'log_cmd() {' >> /etc/bash.bashrc
RUN echo '    history -a' >> /etc/bash.bashrc
RUN echo '    local cmd=$(history 1 | sed "s/^[ ]*[0-9]\+[ ]*//")' >> /etc/bash.bashrc
RUN echo '    if [ -n "$cmd" ]; then' >> /etc/bash.bashrc
RUN echo '        local d=$(date +"%Y-%m-%d %H:%M:%S")' >> /etc/bash.bashrc
RUN echo '        echo "$d | $(whoami) | ${SSH_CLIENT%% *} | $(pwd) | $cmd" >> /var/log/ssh_sessions/commands.log' >> /etc/bash.bashrc
RUN echo '    fi' >> /etc/bash.bashrc
RUN echo '}' >> /etc/bash.bashrc
RUN echo 'export PROMPT_COMMAND="log_cmd"' >> /etc/bash.bashrc
RUN echo 'export PS1="\[\033[1;31m\]🔥\[\033[0m\]\[\033[1;33m\]\u@\h\[\033[0m\]:\[\033[1;36m\]\w\[\033[0m\]\\$ "' >> /etc/bash.bashrc
RUN echo 'alias ls="ls --color=auto"' >> /etc/bash.bashrc
RUN echo 'alias ll="ls -la --color=auto"' >> /etc/bash.bashrc

RUN cp /etc/bash.bashrc /root/.bashrc && \
    cp /etc/bash.bashrc /home/admin/.bashrc && \
    chown admin:admin /home/admin/.bashrc

RUN ssh-keygen -A -q -N ""
COPY ssh_Logger.py /ssh_Logger.py
RUN chmod +x /ssh_Logger.py
# Create fake files and directories to make it look real
RUN mkdir -p /home/admin/Documents /home/admin/Downloads /home/admin/Desktop
RUN echo "TODO: Change default passwords" > /home/admin/notes.txt
RUN echo "192.168.1.1 - router" > /home/admin/network.txt
RUN echo "admin:Admin123!" > /home/admin/passwords.txt
RUN echo "Confidential: Project details..." > /home/admin/secret.txt
RUN echo "#!/bin/bash\necho 'System backup script'" > /home/admin/backup.sh
RUN chmod +x /home/admin/backup.sh
RUN mkdir -p /home/admin/.ssh && touch /home/admin/.bash_history /home/admin/.ssh/authorized_keys

# Create fake system files
RUN echo "Server configuration" > /etc/server.conf
RUN echo "Database connection string" > /root/db_credentials.txt

# Make some files look important
RUN chown admin:admin /home/admin/*
EXPOSE 22
CMD ["python3", "/ssh_Logger.py"]