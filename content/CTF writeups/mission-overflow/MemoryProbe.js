export default class MemoryProbe {
    constructor(consoleElement) {
        this.consoleElement = consoleElement;
        this.state = 'active';
        this.userInput = '';

        this.outputArea = document.createElement('div');
        this.inputLine = document.createElement('div');
        this.inputLine.innerHTML = `<span>&gt; </span><span class="input-text"></span><span class="cursor">_</span>`;
        this.consoleElement.append(this.outputArea, this.inputLine);
        
        this.inputTextSpan = this.inputLine.querySelector('.input-text');
        this.handleKeyPress = this.handleKeyPress.bind(this);
    }

    start() {
        this.outputArea.innerHTML = `
            <p style="color:#ffff00;">H3X N0V4 Memory Probe v1.7</p>
            <p>Enter data payload to analyze process memory.</p>
            <p>WARNING: Unstable buffer. Payloads > 300 bytes may cause heap corruption.</p>
        `;
        this.windowEl.addEventListener('keydown', this.handleKeyPress);
    }
    
    stop() {
        if (this.windowEl) {
            this.windowEl.removeEventListener('keydown', this.handleKeyPress);
        }
    }

    handleKeyPress(event) {
        if (this.state !== 'active') return;

        event.preventDefault();
        event.stopPropagation();

        if (event.key === 'Enter') {
            this.outputArea.innerHTML += `<br><p>&gt; ${this.userInput}</p>`;
            this.outputArea.innerHTML += `<p style="color:orange;">[ANALYSIS] Payload processed. No leaks found. Buffer stable.</p>`;
            this.userInput = '';
        } else if (event.key === 'Backspace') {
            this.userInput = this.userInput.slice(0, -1);
        } else if (event.key.length === 1) {
            this.userInput += event.key;
        }

        this.inputTextSpan.textContent = this.userInput;
        
        if (this.userInput.length > 300) {
            this.triggerGlitch();
        }
    }

    triggerGlitch() {
        this.state = 'glitched';
        
        this.outputArea.innerHTML += `<br><p>&gt; ${this.userInput.slice(0, 40)}...<span style="color:red;">[BUFFER OVERFLOW]</span></p>`;
        
        let glitchText = `
            <p style="color:red;">[!!!] HEAP CORRUPTION DETECTED... SEGMENTATION FAULT [!!!]</p>
            <p style="color:red;">... DUMPING STACK ...</p>
            <p>0x41414141 0x41414141 0x41414141</p>
            <p style="color:#ffff00;">LEAKED POINTER -> secondary_challenge_loader()</p>
            <p style="color:#00ffff;">HINT: The next challenge isn't a file, it's a running process.</p>
            <p style="color:#00ffff;">Find the 'Timebomb' service on the network.</p>
        `;

        this.inputLine.style.display = 'none';
        
        let i = 0;
        const typeGlitch = () => {
            if (i < glitchText.length) {
                this.outputArea.innerHTML += glitchText[i];
                i++;
                this.consoleElement.scrollTop = this.consoleElement.scrollHeight;
                setTimeout(typeGlitch, 10);
            }
        };
        typeGlitch();
    }
}
