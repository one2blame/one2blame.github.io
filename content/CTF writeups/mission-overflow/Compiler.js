export default class Compiler {
    constructor(consoleElement) {
        this.consoleElement = consoleElement;
        this.outputArea = document.createElement('span');
        this.consoleElement.append(this.outputArea);

        this.outputInterval = null;

        // NEW: Themed filenames for the Xorfidential project
        this.files = [
            "src/kernel_interface.c",
            "src/payload_constructor.c",
            "src/canary_bypass.c",
            "src/post_exploit/iam_module.c",
            "src/main.c"
        ];
    }

    addLog(text, color = "#00ff00", isHtml = false) {
        const lineElement = document.createElement('span');
        lineElement.style.display = 'block';
        lineElement.style.color = color;

        if (isHtml) {
            lineElement.innerHTML = text;
        } else {
            lineElement.textContent = text;
        }
        
        this.outputArea.appendChild(lineElement);
        this.consoleElement.scrollTop = this.consoleElement.scrollHeight;
    }

    start() {
        const runBuild = () => {
            let fileIndex = 0;
            
            const compileNext = () => {
                if (fileIndex < this.files.length) {
                    const file = this.files[fileIndex];
                    this.addLog(`Compiling ${file}...`);
                    
                    setTimeout(() => {
                        this.addLog(`  -> [ OK ]`, '#00ffff');

                        // --- NEW: Add contextual hints based on the file being "compiled" ---
                        if (file.includes("canary_bypass")) {
                            this.addLog(`     <span style="color:#ffff00;">DEBUG:</span> Stack canary check is active. Value seems predictable based on initial input vector.`, '#a9a9a9', true);
                            this.addLog(`     <span style="color:#ffff00;">DEBUG:</span> Function pointer 'action_ptr' found in struct. Potential overwrite target.`, '#a9a9a9', true);
                        }
                        if (file.includes("iam_module")) {
                            this.addLog(`     <span style="color:orange;">WARNING:</span> User metadata tags are uninitialized. This may affect cloud pivot stage. Check IAM user tags.`, '#a9a9a9', true);
                            this.addLog(`     <span style="color:#00ffff;">INFO:</span> Linking against policy descriptor: '********consoleElement-policy'. Ensure GetPolicy permissions.`, '#a9a9a9', true);
                        }
                        
                        fileIndex++;
                        setTimeout(compileNext, Math.random() * 300 + 100);
                    }, Math.random() * 600 + 200);
                } else {
                    // Linking phase
                    this.addLog(`\nLinking all object files...`);
                    setTimeout(() => {
                        this.addLog(`\nPayload compiled successfully. Ready for deployment.`, '#ffff00');
                        this.addLog(`\nAttempting connection: nc xorfidential-dc33.hexnova.quest 8888.`, '#ffff00');
                        // Loop the build process
                        this.outputInterval = setTimeout(runBuild, 5000);
                    }, 1000);
                }
            };
            
            this.outputArea.innerHTML = ''; // Clear for next build
            this.addLog(`Starting new build cycle for 'Xorfidential' payload at ${new Date().toLocaleTimeString()}`);
            compileNext();
        };
        runBuild();
    }

    stop() {
        clearTimeout(this.outputInterval);
    }
}
