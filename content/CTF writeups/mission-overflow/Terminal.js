export default class Terminal {
    constructor(consoleElement) {
        this.consoleElement = consoleElement;
        this.outputArea = document.createElement('span');
        this.cursor = document.createElement('span');
        this.cursor.className = 'cursor';
        this.cursor.textContent = '_';
        this.consoleElement.append(this.outputArea, this.cursor);
        
        this.messageIndex = Math.floor(Math.random() * this.hackerMessages.length);
        this.typeSpeed = 30;
        this.outputInterval = null;
    }

    hackerMessages = [
        " \n",       
        "       > Initializing secure connection to Cloud Village...",
        "       > Accessing encrypted data stream...",
        "$> ./payload-decryptor ",
        "       > Decrypting payload: [██████████] 99%",
        "       > WARNING: Intrusion attempt detected.",
        "       > Compiling kernel modules: [SUCCESS]",
        "       > Launching brute-force attack: [ERROR]",
        "$> ./exploit.sh",
        "       > Downloading classified schematics.",
        "       > SYN flood attack initiated.",
        "       > Analyzing network topology...",
        "       > Establishing covert channel via port 9999.",
        "       > Log purge: [ERROR]",
        "$> Welcome, user 'phantom-aws'.",
        "----------------------------",
    ];

    typeLine(line, callback) {
        let charIndex = 0;
        const lineElement = document.createElement('span');
        lineElement.style.display = 'block'; // Each message on a new line
        this.outputArea.appendChild(lineElement);

        const typeChar = () => {
            if (charIndex < line.length) {
                lineElement.textContent += line.charAt(charIndex);
                charIndex++;
                this.consoleElement.scrollTop = this.consoleElement.scrollHeight;
                setTimeout(typeChar, this.typeSpeed + (Math.random() * 20 - 10));
            } else {
                if (callback) callback();
            }
        };
        typeChar();
    }

    start() {
        const displayNextMessage = () => {
            if (this.messageIndex >= this.hackerMessages.length) {
                this.messageIndex = 0; // Loop
            }
            this.typeLine(this.hackerMessages[this.messageIndex], () => {
                this.messageIndex++;
                this.outputInterval = setTimeout(displayNextMessage, Math.random() * 1500 + 500);
            });
        };
        displayNextMessage();
    }
    
    stop() {
        clearTimeout(this.outputInterval);
    }
}