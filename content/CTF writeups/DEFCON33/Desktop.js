import Terminal from "./Terminal.js"
import Ssh from "./Ssh.js"
import Compiler from "./Compiler.js"
import Timebomb from "./Timebomb.js"
import MemoryProbe from "./MemoryProbe.js"
import H3xCLI from "./H3x-CLI.js"

export default class Desktop {
  /**
   * Initializes the Desktop environment.
   * @param {HTMLElement} desktopEl - The main desktop container element.
   * @param {HTMLElement} taskbarAppsEl - The container for running app icons on the taskbar.
   */
  constructor(desktopEl, taskbarAppsEl) {
    this.desktop = desktopEl
    this.taskbarApps = taskbarAppsEl

    // The App Registry maps a string key to an application class and its window title.
    this.appRegistry = {
      terminal: { class: Terminal, title: "Terminal" },
      ssh: { class: Ssh, title: "SSH Session" },
      compiler: { class: Compiler, title: "XORfidential" },
      timebomb: { class: Timebomb, title: "TimeBomb" },
      memory_probe: { class: MemoryProbe, title: "Memory Probe" },
      h3x_cli: { class: H3xCLI, title: "H3x-CLI" },
    }

    // State variables
    this.windowCounter = 0
    this.activeZIndex = 100
    this.isDragging = false
    this.dragTarget = null
    this.offsetX = 0
    this.offsetY = 0

    this.init()
  }

  /**
   * Kicks off the desktop setup.
   */
  init() {
    this.setupHamburgerMenu()
    this.attachEventListeners()
    this.createWindow("terminal") // Start with one terminal window open.
  }

  /**
   * Sets up all the logic for the hamburger menu in the taskbar.
   */
  setupHamburgerMenu() {
    const menuContainer = document.getElementById("hamburger-menu")
    const icon = menuContainer.querySelector(".hamburger-icon")
    const panel = menuContainer.querySelector(".menu-panel")

    // Toggle the menu panel when the icon is clicked
    icon.addEventListener("click", (e) => {
      e.stopPropagation() // Prevent the click from immediately closing the menu
      menuContainer.classList.toggle("open")
    })

    // Launch an app when a menu item is clicked
    panel.addEventListener("click", (e) => {
      if (e.target.tagName === "LI") {
        const appType = e.target.dataset.app
        if (appType) {
          this.createWindow(appType)
          menuContainer.classList.remove("open") // Close menu after selection
        }
      }
    })

    // Close the menu if you click anywhere else on the page
    document.addEventListener("click", () => {
      if (menuContainer.classList.contains("open")) {
        menuContainer.classList.remove("open")
      }
    })
  }

  /**
   * Attaches global event listeners for desktop functionality.
   */
  attachEventListeners() {
    // Event delegation for window interactions
    this.desktop.addEventListener("mousedown", this.handleMouseDown.bind(this))
    this.desktop.addEventListener("click", this.handleWindowControls.bind(this))
    document.addEventListener("mousemove", this.handleMouseMove.bind(this))
    document.addEventListener("mouseup", this.handleMouseUp.bind(this))
    this.taskbarApps.addEventListener(
      "click",
      this.handleTaskbarClick.bind(this),
    )
  }

  /**
   * Creates a new application window on the desktop.
   * @param {string} appType - The key of the app from the appRegistry.
   */
  createWindow(appType) {
    const appInfo = this.appRegistry[appType]
    if (!appInfo) {
      console.error("Unknown app type:", appType)
      return
    }

    this.windowCounter++
    const windowId = `window-${this.windowCounter}`
    const windowTitle = `${appInfo.title}-${this.windowCounter}`

    const windowEl = document.createElement("div")
    windowEl.className = "window"
    windowEl.id = windowId
    windowEl.style.left = `${15 + (this.windowCounter % 10) * 2}vw`
    windowEl.style.top = `${15 + (this.windowCounter % 10) * 3}vh`

    windowEl.innerHTML = `
            <div class="window-header">
                <span class="title">${windowTitle}</span>
                <div class="window-controls">
                    <span class="minimize-btn" title="Minimize"></span>
                    <span class="maximize-btn" title="Maximize"></span>
                    <span class="close-btn" title="Close"></span>
                </div>
            </div>
            <div class="window-content">
                <div class="hacker-console"></div>
            </div>
        `
    this.desktop.appendChild(windowEl)

    setTimeout(() => windowEl.classList.add("open"), 10)

    const taskbarEntry = this.createTaskbarEntry(windowId, windowTitle)
    this.taskbarApps.appendChild(taskbarEntry)

    const consoleEl = windowEl.querySelector(".hacker-console")
    const appInstance = new appInfo.class(consoleEl)
    appInstance.start()

    windowEl.appInstance = appInstance

    this.bringToFront(windowEl)
  }

  /**
   * Creates a corresponding entry on the taskbar for a new window.
   * @param {string} windowId
   * @param {string} windowTitle
   * @returns {HTMLElement}
   */
  createTaskbarEntry(windowId, windowTitle) {
    const taskbarEntry = document.createElement("div")
    taskbarEntry.className = "taskbar-entry"
    taskbarEntry.dataset.windowId = windowId
    const icon = "&#9672;" // Generic icon
    taskbarEntry.innerHTML = `<span>${icon}</span> <span>${windowTitle}</span>`
    return taskbarEntry
  }

  /**
   * Brings a specified window to the front and marks it as active.
   * @param {HTMLElement} windowEl
   */
  bringToFront(windowEl) {
    document
      .querySelectorAll(".window")
      .forEach((win) => win.classList.remove("active"))
    document
      .querySelectorAll(".taskbar-entry")
      .forEach((entry) => entry.classList.remove("active"))

    if (windowEl && !windowEl.classList.contains("minimized")) {
      windowEl.style.zIndex = ++this.activeZIndex
      windowEl.classList.add("active")

      const taskbarEntry = this.taskbarApps.querySelector(
        `.taskbar-entry[data-window-id="${windowEl.id}"]`,
      )
      if (taskbarEntry) {
        taskbarEntry.classList.add("active")
      }
    }
  }

  /**
   * Handles starting a drag operation on a window.
   * @param {MouseEvent} e
   */
  handleMouseDown(e) {
    const windowHeader = e.target.closest(".window-header")
    const targetWindow = e.target.closest(".window")

    if (!targetWindow) return

    this.bringToFront(targetWindow)

    if (windowHeader && !targetWindow.classList.contains("maximized")) {
      this.isDragging = true
      this.dragTarget = targetWindow
      this.offsetX = e.clientX - this.dragTarget.getBoundingClientRect().left
      this.offsetY = e.clientY - this.dragTarget.getBoundingClientRect().top
      this.dragTarget.style.cursor = "grabbing"
    }
  }

  /**
   * Handles moving a window during a drag operation.
   * @param {MouseEvent} e
   */
  handleMouseMove(e) {
    if (!this.isDragging || !this.dragTarget) return
    e.preventDefault()

    let newX = e.clientX - this.offsetX
    let newY = e.clientY - this.offsetY

    const taskbarHeight = 40
    newX = Math.max(
      0,
      Math.min(newX, this.desktop.clientWidth - this.dragTarget.clientWidth),
    )
    newY = Math.max(
      0,
      Math.min(
        newY,
        this.desktop.clientHeight -
          this.dragTarget.clientHeight -
          taskbarHeight,
      ),
    )

    this.dragTarget.style.left = `${newX}px`
    this.dragTarget.style.top = `${newY}px`
  }

  /**
   * Handles ending a drag operation.
   */
  handleMouseUp() {
    if (this.dragTarget) {
      this.dragTarget.style.cursor = "grab"
    }
    this.isDragging = false
    this.dragTarget = null
  }

  /**
   * Handles clicks on window control buttons (min, max, close).
   * @param {MouseEvent} e
   */
  handleWindowControls(e) {
    const targetWindow = e.target.closest(".window")
    if (!targetWindow) return

    if (e.target.matches(".minimize-btn")) {
      targetWindow.classList.add("minimized")
      targetWindow.classList.remove("open", "active")
      const taskbarEntry = this.taskbarApps.querySelector(
        `.taskbar-entry[data-window-id="${targetWindow.id}"]`,
      )
      if (taskbarEntry) taskbarEntry.classList.remove("active")
    } else if (e.target.matches(".maximize-btn")) {
      targetWindow.classList.toggle("maximized")
    } else if (e.target.matches(".close-btn")) {
      if (targetWindow.appInstance) targetWindow.appInstance.stop()
      const taskbarEntry = this.taskbarApps.querySelector(
        `.taskbar-entry[data-window-id="${targetWindow.id}"]`,
      )
      if (taskbarEntry) taskbarEntry.remove()
      targetWindow.remove()
    }
  }

  /**
   * Handles clicks on taskbar entries to focus, minimize, or restore windows.
   * @param {MouseEvent} e
   */
  handleTaskbarClick(e) {
    const taskbarEntry = e.target.closest(".taskbar-entry")
    if (!taskbarEntry) return

    const windowId = taskbarEntry.dataset.windowId
    const targetWindow = document.getElementById(windowId)

    if (!targetWindow) return

    if (targetWindow.classList.contains("active")) {
      targetWindow.querySelector(".minimize-btn").click()
    } else if (targetWindow.classList.contains("minimized")) {
      targetWindow.classList.remove("minimized")
      targetWindow.classList.add("open")
      this.bringToFront(targetWindow)
    } else {
      this.bringToFront(targetWindow)
    }
  }
}
