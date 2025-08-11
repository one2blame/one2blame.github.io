export default class Ssh {
  constructor(consoleElement) {
    this.consoleElement = consoleElement
    this.outputArea = document.createElement("span")
    this.cursor = document.createElement("span")
    this.cursor.className = "cursor"
    this.cursor.textContent = "_"
    this.consoleElement.append(this.outputArea, this.cursor)

    this.typeSpeed = 50
    this.outputInterval = null
    this.websites = [
      "api.github.com",
      "corp.internal.net",
      "classified.mil",
      "mainframe.gov",
      "dev.local",
    ]
  }

  typeLine(line, callback) {
    let charIndex = 0
    const lineElement = document.createElement("span")
    lineElement.style.display = "block"
    this.outputArea.appendChild(lineElement)

    const typeChar = () => {
      if (charIndex < line.length) {
        lineElement.textContent += line.charAt(charIndex)
        charIndex++
        this.consoleElement.scrollTop = this.consoleElement.scrollHeight
        setTimeout(typeChar, this.typeSpeed)
      } else {
        if (callback) callback()
      }
    }
    typeChar()
  }

  start() {
    const runSession = () => {
      const target =
        this.websites[Math.floor(Math.random() * this.websites.length)]
      const steps = [
        `ssh root@${target} -p 22`,
        `Connecting to ${target}...`,
        `Connection established.`,
        `Authenticating with private key "id_rsa"...`,
        Math.random() > 0.4
          ? `Permission denied (private key).`
          : `Authentication successful.`,
        `Retrying in 5 seconds...`,
        ` `, // Blank line for spacing
      ]

      let currentStep = 0
      const processNextStep = () => {
        if (currentStep < steps.length) {
          this.typeLine(steps[currentStep], () => {
            currentStep++
            // Add a longer delay before retrying
            const delay = steps[currentStep - 1].includes("Retrying")
              ? 3000
              : Math.random() * 400 + 100
            setTimeout(processNextStep, delay)
          })
        } else {
          // Loop the session
          this.outputInterval = setTimeout(runSession, 1000)
        }
      }
      processNextStep()
    }
    runSession()
  }

  stop() {
    clearTimeout(this.outputInterval)
  }
}
