// js/Timebomb.js

export default class Timebomb {
  constructor(consoleElement) {
    this.consoleElement = consoleElement
    this.state = "prompt" // states: 'prompt', 'counting', 'aborted', 'detonated'

    // Create the UI areas
    this.promptArea = document.createElement("div")
    this.timerArea = document.createElement("div")
    this.timerArea.className = "timebomb-display"
    this.timerArea.style.display = "none" // Initially hidden
    this.consoleElement.append(this.promptArea, this.timerArea)

    // Bind the event listener once
    this.handleKeyPress = this.handleKeyPress.bind(this)
  }

  start() {
    this.promptArea.innerHTML = `
            <p>Remote explosive device detected. Signal is active.</p>
            <p>Mainframe connection established.</p>
            <p>Proceed with arming sequence? [Y/N]</p>
            <p>  Connecting to TIMEBOMB: nc timebomb-dc33.hexnova.quest 9999 </p>
        `
    // Listen for user input
    document.addEventListener("keydown", this.handleKeyPress)
  }

  stop() {
    // Clean up when the window is closed
    document.removeEventListener("keydown", this.handleKeyPress)
    if (this.countdownInterval) {
      clearInterval(this.countdownInterval)
    }
  }

  handleKeyPress(event) {
    // Only react if the prompt is active and the key is Y or N
    if (this.state !== "prompt") return

    if (event.key.toLowerCase() === "y") {
      this.state = "counting"
      this.startCountdown()
    } else if (event.key.toLowerCase() === "n") {
      this.state = "aborted"
      this.promptArea.innerHTML += `<p style="color: #ffff00;">&gt; ARMING SEQUENCE ABORTED BY USER.</p>`
      document.removeEventListener("keydown", this.handleKeyPress)
    }
  }

  startCountdown() {
    // Hide prompt, show timer
    this.promptArea.style.display = "none"
    this.timerArea.style.display = "flex"

    // Add a class to the parent window for styling
    const windowEl = this.consoleElement.closest(".window")
    if (windowEl) {
      windowEl.classList.add("timer-active")
    }

    let secondsRemaining = 30 // 30 seconds (in seconds)

    this.countdownInterval = setInterval(() => {
      if (secondsRemaining <= 0) {
        clearInterval(this.countdownInterval)
        this.state = "detonated"
        this.timerArea.innerHTML = "DETONATED"
        if (windowEl) {
          windowEl.classList.remove("timer-active")
          windowEl.classList.add("detonated") // For a different final style
        }
        return
      }

      secondsRemaining--

      const minutes = Math.floor(secondsRemaining / 60)
      const seconds = secondsRemaining % 60

      // Format to MM:SS
      const displayTime = `${minutes.toString().padStart(2, "0")}:${seconds.toString().padStart(2, "0")}`
      this.timerArea.textContent = displayTime
    }, 1000)
  }
}
