export default class H3xCLI {
  constructor(consoleElement) {
    // The main window content area for this app
    this.consoleElement = consoleElement

    // Game state properties, initialized here
    this.gameProgress = 0
    this.inventory = []
    this.systemAccess = false
    this.currentDir = "/"
    this.userInput = ""
    this.isGameOver = false

    // --- Game Data and Logic ---
    // Moved the game state logic into a separate, more manageable object.
    this.gameStates = {
      0: {
        intro: [
          "Booting secure mission terminal...",
          "Welcome, Agent.",
          "Your mission: Infiltrate 'Orion Corp' and extract 'Project Chimera 2' blueprints.",
          "Type 'help' for commands or 'start' to begin.",
        ],
        commands: {
          start: (game) => {
            if (game.gameProgress === 0) {
              game.writeToTerminal("Initiating network scan...")
              game.gameProgress = 1
              setTimeout(() => {
                game.writeToTerminal(
                  "Scan complete. Vulnerable port found on 192.168.1.100.",
                )
                game.writeToTerminal(
                  "You can now 'scan 192.168.1.100' or 'login 192.168.1.100'.",
                )
              }, 1500)
            } else {
              game.writeToTerminal("Mission already in progress.")
            }
          },
          help: (game) =>
            game.writeToTerminal("Available commands: start, help, status"),
        },
      },
      1: {
        commands: {
          scan: (game, target) => {
            if (target === "192.168.1.100") {
              game.writeToTerminal("Scanning 192.168.1.100...")
              setTimeout(() => {
                game.writeToTerminal(
                  "Port 22 (SSH) open. Weak password found: 'admin123'.",
                )
              }, 1500)
            } else {
              game.writeToTerminal("Invalid target.")
            }
          },
          login: (game, target) => {
            if (target === "192.168.1.100") {
              game.writeToTerminal("Attempting login to 192.168.1.100...")
              setTimeout(() => {
                game.writeToTerminal(
                  '<span style="color:#00ffff;">Login successful! Welcome to Orion Corp Intranet.</span>',
                  { isHtml: true },
                )
                game.systemAccess = true
                game.gameProgress = 2
                game.writeToTerminal(
                  "You can now 'ls' (list files) or 'cd' (change directory).",
                )
              }, 2000)
            } else {
              game.writeToTerminal("Invalid target for login.")
            }
          },
          help: (game) =>
            game.writeToTerminal(
              "Available commands: scan [ip], login [ip], status, help",
            ),
        },
      },
      2: {
        commands: {
          ls: (game, dir) => {
            if (game.currentDir === "/") {
              if (!dir || dir === ".")
                game.writeToTerminal("Files: security_log.txt, /data")
              else game.writeToTerminal("ls: directory not found.")
            } else if (game.currentDir === "/data") {
              if (!dir || dir === ".")
                game.writeToTerminal(
                  "Files: financial_records.db, Project_Chimera.zip",
                )
              else game.writeToTerminal("ls: directory not found.")
            }
          },
          cd: (game, dir) => {
            if (dir === "data" || dir === "/data") {
              game.currentDir = "/data"
              game.writeToTerminal("Changed directory to /data.")
              game.writeToTerminal(
                "Now you can 'download Project_Chimera.zip'.",
              )
              game.gameProgress = 3
            } else if (dir === "/" || dir === "..") {
              game.currentDir = "/"
              game.writeToTerminal("Changed directory to /")
            } else {
              game.writeToTerminal("cd: directory not found.")
            }
          },
          download: (game, file) => {
            if (file === "Project_Chimera.zip" && game.gameProgress === 3) {
              game.writeToTerminal("Downloading Project_Chimera.zip...")
              setTimeout(() => {
                game.writeToTerminal(
                  '<span style="color:#00ff00;">Download complete.</span>',
                  { isHtml: true },
                )
                game.inventory.push("Project_Chimera.zip")
                game.endGame()
              }, 2500)
            } else {
              game.writeToTerminal(
                "download: file not found or not in current directory.",
              )
            }
          },
          help: (game) =>
            game.writeToTerminal(
              "Available commands: ls, cd [directory], download [file], status, help",
            ),
        },
      },
    }
  }

  start() {
    this.initDOM()
    this.bindEvents()
    this.displayIntro()
  }

  stop() {
    // Clean up the event listener when the window is closed
    document.removeEventListener("keydown", this.handleKeyPress)
  }

  initDOM() {
    this.consoleElement.classList.add("adventure-game-wrapper")
    this.consoleElement.innerHTML = `
            <div class="terminal-output"></div>
            <div class="input-line">
                <span class="prompt">agent@orion:~$ </span>
                <span class="input-text"></span>
                <span class="cursor">_</span>
            </div>
            <div class="end-message-container" style="display: none;"></div>
        `

    this.output = this.consoleElement.querySelector(".terminal-output")
    this.inputTextSpan = this.consoleElement.querySelector(".input-text")
    this.endMessageContainer = this.consoleElement.querySelector(
      ".end-message-container",
    )

    const promptEl = this.consoleElement.querySelector(".prompt")
    if (promptEl) {
      promptEl.style.paddingRight = "4px"
    }
  }

  bindEvents() {
    this.handleKeyPress = this.handleKeyPress.bind(this)
    document.addEventListener("keydown", this.handleKeyPress)
    this.consoleElement.addEventListener("click", () => {
      /* The keydown listener on document handles focus logic */
    })
  }

  displayIntro() {
    this.gameStates[0].intro.forEach((line) => this.writeToTerminal(line))
  }

  handleKeyPress(e) {
    if (this.isGameOver) return // Stop all input if game is over

    const parentWindow = this.consoleElement.closest(".window")
    if (!parentWindow || !parentWindow.classList.contains("active")) {
      return
    }

    e.preventDefault()
    e.stopPropagation()

    if (e.key === "Enter") {
      if (this.userInput.trim() === "") return
      this.processCommand(this.userInput)
      this.userInput = ""
    } else if (e.key === "Backspace") {
      this.userInput = this.userInput.slice(0, -1)
    } else if (e.key.length === 1) {
      this.userInput += e.key
    }

    this.inputTextSpan.textContent = this.userInput

    // NEW: Check for buffer overflow condition
    if (this.userInput.length > 200) {
      this.triggerRansomware()
    }
  }

  processCommand(commandLine) {
    this.writeToTerminal(
      `<span class="prompt">agent@orion:~$</span> ${commandLine}`,
      { isHtml: true },
    )

    const parts = commandLine.trim().toLowerCase().split(/\s+/)
    const command = parts[0]
    const args = parts.slice(1)

    const currentState =
      this.gameStates[this.gameProgress] || this.gameStates[2]

    if (command === "status") {
      this.showStatus()
      return
    }

    if (currentState.commands[command]) {
      currentState.commands[command](this, ...args)
    } else {
      this.writeToTerminal(`Command not found: '${command}'. Type 'help'.`)
    }
  }

  writeToTerminal(text, options = {}) {
    const { isHtml = false } = options
    const line = document.createElement("div")
    line.classList.add("terminal-line")
    if (isHtml) {
      line.innerHTML = text
    } else {
      line.textContent = text
    }
    this.output.appendChild(line)
    this.output.scrollTop = this.output.scrollHeight
  }

  showStatus() {
    this.writeToTerminal(`Current Progress: Stage ${this.gameProgress}/3`)
    this.writeToTerminal(
      `Inventory: ${this.inventory.length > 0 ? this.inventory.join(", ") : "Empty"}`,
    )
    this.writeToTerminal(
      `System Access: ${this.systemAccess ? '<span style="color:#00ff00;">Granted</span>' : '<span style="color:red;">Denied</span>'}`,
      { isHtml: true },
    )
  }

  endGame() {
    this.isGameOver = true
    this.consoleElement.querySelector(".input-line").style.display = "none"
    this.endMessageContainer.style.display = "block"
    this.endMessageContainer.style.textAlign = "center"
    this.endMessageContainer.style.padding = "20px"
    this.endMessageContainer.innerHTML = `
            <h2 style="color:#00ff00;">Mission Accomplished!</h2>
            <p>You have successfully extracted 'Project Chimera' blueprints.</p>
            <p>Orion Corp's secrets are now yours. Well done, Agent.</p>
        `
    this.stop()
  }

  // NEW: Function to handle the ransomware "exploit"
  triggerRansomware() {
    this.isGameOver = true
    this.stop() // Stop listening for normal input

    const inputLine = this.consoleElement.querySelector(".input-line")
    if (inputLine) {
      inputLine.style.display = "none"
    }

    this.output.innerHTML += `
            <br>
            <p style="color:red;">[FATAL] STACK BUFFER OVERFLOW AT 0x77A1B3CC</p>
            <p style="color:red;">[FATAL] MEMORY CORRUPTION DETECTED. SHUTTING DOWN...</p>
        `
    this.consoleElement.scrollTop = this.consoleElement.scrollHeight

    setTimeout(() => {
      this.output.innerHTML = "" // Clear the screen
      this.endMessageContainer.style.display = "block"
      this.endMessageContainer.style.textAlign = "center"
      this.endMessageContainer.style.padding = "20px"
      this.endMessageContainer.style.border = "2px solid red"
      this.endMessageContainer.style.boxShadow = "0 0 15px rgba(255, 0, 0, 0.7)"
      this.endMessageContainer.innerHTML = `
                <h2 style="color:red; text-shadow: 0 0 5px red;">SYSTEM COMPROMISED</h2>
                <p style="color:#ffff00;">All your files are encrypted.</p>
                <p>Visit the dashboard to learn more.</p>
                <br>
                <p style="font-size: 1.2em; color: #00ffff;">RANSOMWARE DASHBOARD:</p>
                <p style="font-size: 1.2em; background: #333; padding: 5px; border-radius: 4px;">https://overflow-dc33.s3.us-west-2.amazonaws.com/e-framework.html</p>
            `
    }, 2000)
  }
}
