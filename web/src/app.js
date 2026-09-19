import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import './app.css'

const connectionStatus = document.getElementById('connection-status')
const reauthLink = document.getElementById('reauth-link')
const notice = document.getElementById('notice')
const devicesElement = document.getElementById('devices')
const tabsElement = document.getElementById('session-tabs')
const terminalsElement = document.getElementById('terminals')
const emptyElement = document.getElementById('terminal-empty')
const closeButton = document.getElementById('close-session')
const interruptButton = document.getElementById('interrupt-session')
const terminalState = document.getElementById('terminal-state')
const encoder = new TextEncoder()

const sessions = new Map()
let activeSessionId = null
let socket = null
let reconnectDelay = 1000
let reconnectTimer = null
let pendingDevice = null
let online = false
let deviceRenderKey = ''

function setNotice(message, tone = 'neutral') {
  notice.textContent = message
  notice.dataset.tone = tone
}

function setConnection(label, state) {
  connectionStatus.textContent = label
  connectionStatus.dataset.state = state
}

function send(message) {
  if (!socket || socket.readyState !== WebSocket.OPEN) return false
  socket.send(JSON.stringify(message))
  return true
}

function encodedBytes(bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function decodedBytes(value) {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index)
  return bytes
}

function sendTerminalBytes(sessionId, bytes) {
  const session = sessions.get(sessionId)
  if (!session?.ready || !online) return false
  for (let offset = 0; offset < bytes.length; offset += 16384) {
    if (!send({ type: 'term_input', sessionId, input: encodedBytes(bytes.subarray(offset, offset + 16384)) })) return false
  }
  return true
}

function renderDevices(deviceDetails) {
  const nextKey = JSON.stringify([online, deviceDetails.map(device => [device.deviceId, device.description,
    device.connected, device.connected ? null : device.lastSeen])])
  if (deviceRenderKey === nextKey) return
  deviceRenderKey = nextKey
  devicesElement.replaceChildren()
  if (!deviceDetails.length) {
    const empty = document.createElement('div')
    empty.className = 'device-empty'
    empty.innerHTML = online
      ? '<span class="onboard-step">01 / SERVER</span><p>Enroll an agent:</p><code>python -m server.admin enroll my-agent --output ~/.config/aetherterm/my-agent.token</code><span class="onboard-step">02 / AGENT</span><p>Start the agent with that private file. The README has the full command.</p>'
      : '<p>Waiting for the server connection.</p>'
    devicesElement.append(empty)
    if (online) setNotice('No device is enrolled yet. Enroll one on the server, then start its agent.')
    return
  }
  for (const device of deviceDetails) {
    const deviceId = device.deviceId
    const button = document.createElement('button')
    button.type = 'button'
    button.className = `device-button${device.connected ? '' : ' offline'}`
    button.disabled = !device.connected
    button.innerHTML = '<span class="device-icon" aria-hidden="true">⌁</span><span class="device-copy"><strong></strong><small></small><span class="device-description"></span><span class="device-activity"></span></span><span class="device-arrow" aria-hidden="true">↗</span>'
    button.querySelector('strong').textContent = deviceId
    button.querySelector('small').textContent = device.connected ? 'ONLINE · OPEN SHELL' : 'OFFLINE · ENROLLED'
    const description = button.querySelector('.device-description')
    description.textContent = device.description || ''
    const activity = button.querySelector('.device-activity')
    activity.textContent = device.connected ? 'Active now' : (device.lastSeen
      ? `Last seen ${new Date(device.lastSeen * 1000).toLocaleString()}` : 'Not seen since server start')
    button.setAttribute('aria-label', `${deviceId}, ${device.connected ? 'online, open shell' : 'offline'}, ${description.textContent} ${activity.textContent}`)
    button.addEventListener('click', () => {
      if (pendingDevice || !online || !device.connected) return
      pendingDevice = deviceId
      if (!send({ type: 'start_session', deviceId })) pendingDevice = null
      else setNotice(`Opening a shell on ${deviceId}…`)
    })
    devicesElement.append(button)
  }
  if (online && !deviceDetails.some(device => device.connected)) {
    setNotice('All enrolled devices are offline. Start an agent to open a shell.')
  } else if (online && !sessions.size && !pendingDevice) {
    setNotice('Choose a connected device to open a shell.', 'success')
  }
}

function fitSession(session) {
  if (activeSessionId !== session.id) return
  session.fit.fit()
  if (session.ready) {
    send({ type: 'resize', sessionId: session.id, cols: session.terminal.cols, rows: session.terminal.rows })
  }
}

function activateSession(sessionId, { focusTerminal = true } = {}) {
  activeSessionId = sessionId
  for (const session of sessions.values()) {
    const active = session.id === sessionId
    session.pane.hidden = !active
    session.tab.setAttribute('aria-selected', String(active))
    session.tab.tabIndex = active ? 0 : -1
  }
  emptyElement.hidden = Boolean(sessionId)
  closeButton.disabled = !sessionId || !online
  const session = sessions.get(sessionId)
  interruptButton.disabled = !session?.ready || !online
  terminalState.textContent = session ? `${session.deviceId.toUpperCase()} · ${session.ready ? 'SHELL READY' : 'STARTING SHELL'}` : 'NO ACTIVE SESSION'
  if (session) requestAnimationFrame(() => {
    fitSession(session)
    if (focusTerminal) session.terminal.focus()
  })
}

function createSession(id, deviceId) {
  const tab = document.createElement('button')
  tab.type = 'button'
  tab.className = 'session-tab'
  tab.setAttribute('role', 'tab')
  tab.id = `session-tab-${id}`
  tab.setAttribute('aria-controls', `session-panel-${id}`)
  tab.textContent = deviceId
  tab.addEventListener('click', () => activateSession(id))
  tabsElement.append(tab)

  const pane = document.createElement('div')
  pane.className = 'terminal-pane'
  pane.setAttribute('role', 'tabpanel')
  pane.id = `session-panel-${id}`
  pane.setAttribute('aria-labelledby', tab.id)
  pane.setAttribute('aria-label', `Terminal on ${deviceId}`)
  terminalsElement.append(pane)

  const terminal = new Terminal({
    cursorBlink: true,
    allowProposedApi: false,
    screenReaderMode: true,
    scrollback: 2000,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
    fontSize: 14,
    lineHeight: 1.28,
    theme: {
      background: '#11191b', foreground: '#dce8e5', cursor: '#e4b467', selectionBackground: '#35645f88',
      black: '#162024', red: '#e68b83', green: '#91c9af', yellow: '#e4b467', blue: '#7eafd0',
      magenta: '#c4a1c9', cyan: '#8fc9c3', white: '#dce8e5', brightBlack: '#607277',
      brightRed: '#f5a29a', brightGreen: '#b5dfc6', brightYellow: '#f3cb84', brightBlue: '#a3c5dc',
      brightMagenta: '#d7b8d9', brightCyan: '#b4e0da', brightWhite: '#f8fcfa'
    }
  })
  const fit = new FitAddon()
  terminal.loadAddon(fit)
  const session = { id, deviceId, tab, pane, terminal, fit, ready: false }
  sessions.set(id, session)
  activateSession(id)
  terminal.open(pane)
  terminal.onData(data => sendTerminalBytes(id, encoder.encode(data)))
  terminal.onBinary(data => sendTerminalBytes(id, Uint8Array.from(data, character => character.charCodeAt(0) & 255)))
  requestAnimationFrame(() => fitSession(session))
}

function removeSession(id) {
  const session = sessions.get(id)
  if (!session) return
  session.terminal.dispose()
  session.pane.remove()
  session.tab.remove()
  sessions.delete(id)
  if (activeSessionId === id) activateSession(sessions.size ? [...sessions.keys()].at(-1) : null)
}

function handleMessage(event) {
  let message
  try { message = JSON.parse(event.data) } catch { return }
  if (message.type === 'device_list') {
    renderDevices(message.deviceDetails || message.devices.map(deviceId =>
      ({ deviceId, description: '', connected: true, lastSeen: null })))
  } else if (message.type === 'session_started') {
    const deviceId = message.deviceId || pendingDevice || 'Agent'
    pendingDevice = null
    createSession(message.sessionId, deviceId)
    setNotice(`Starting shell on ${deviceId}…`)
  } else if (message.type === 'session_ready') {
    const session = sessions.get(message.sessionId)
    if (!session) return
    session.ready = true
    session.tab.classList.add('ready')
    fitSession(session)
    if (activeSessionId === session.id) {
      terminalState.textContent = `${session.deviceId.toUpperCase()} · SHELL READY`
      interruptButton.disabled = false
    }
    setNotice(`Shell ready on ${session.deviceId}. Type directly in the terminal.`, 'success')
  } else if (message.type === 'term_data') {
    const session = sessions.get(message.sessionId)
    if (session) session.terminal.write(decodedBytes(message.data))
  } else if (message.type === 'session_closed') {
    const session = sessions.get(message.sessionId)
    if (message.reason) setNotice(message.reason, 'error')
    else if (session) setNotice(`Shell closed on ${session.deviceId}.`, 'neutral')
    removeSession(message.sessionId)
  } else if (message.type === 'error') {
    pendingDevice = null
    setNotice(message.message || 'The request failed.', 'error')
  }
}

function connect() {
  clearTimeout(reconnectTimer)
  reconnectTimer = null
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const connection = new WebSocket(`${protocol}//${window.location.host}/ws`, 'aetherterm.v1')
  socket = connection
  setConnection('Connecting', 'connecting')
  connection.addEventListener('open', () => {
    if (socket !== connection) return
    online = true
    reauthLink.hidden = true
    reconnectDelay = 1000
    setConnection('Server connected', 'online')
    setNotice('Choose a connected device to open a shell.', 'success')
    send({ type: 'list_devices' })
  })
  connection.addEventListener('message', handleMessage)
  connection.addEventListener('close', async event => {
    if (socket !== connection) return
    online = false
    pendingDevice = null
    for (const id of [...sessions.keys()]) removeSession(id)
    renderDevices([])
    setConnection('Server offline', 'offline')
    if (event.code === 1008) {
      setNotice('Access expired or was revoked. Sign in again.', 'error')
      reauthLink.hidden = false
      return
    }
    try {
      const response = await fetch('/auth/status', { cache: 'no-store' })
      if (socket !== connection) return
      if (response.status === 401) {
        setNotice('Access expired or was revoked. Sign in again.', 'error')
        reauthLink.hidden = false
        return
      }
    } catch { /* Server is offline; retry below. */ }
    if (socket !== connection) return
    setNotice('Connection lost. Retrying; previous shells are closed.', 'error')
    reconnectTimer = setTimeout(connect, reconnectDelay)
    reconnectDelay = Math.min(reconnectDelay * 2, 30000)
  })
}

tabsElement.addEventListener('keydown', event => {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key) || !sessions.size) return
  event.preventDefault()
  const ids = [...sessions.keys()]
  const currentIndex = ids.indexOf(activeSessionId)
  const nextIndex = event.key === 'Home' ? 0 : event.key === 'End' ? ids.length - 1
    : (currentIndex + (event.key === 'ArrowRight' ? 1 : -1) + ids.length) % ids.length
  const nextId = ids[nextIndex]
  activateSession(nextId, { focusTerminal: false })
  sessions.get(nextId).tab.focus()
})

window.addEventListener('offline', () => {
  if (socket && socket.readyState < WebSocket.CLOSING) socket.close()
})
window.addEventListener('online', () => {
  if (!online && reconnectTimer !== null) connect()
})

document.getElementById('refresh-devices').addEventListener('click', () => {
  if (!send({ type: 'list_devices' })) setNotice('The server is offline. Wait for reconnection.', 'error')
})
closeButton.addEventListener('click', () => {
  if (activeSessionId) send({ type: 'close_session', sessionId: activeSessionId })
})
interruptButton.addEventListener('click', () => {
  if (!activeSessionId || interruptButton.disabled) return
  const sent = sendTerminalBytes(activeSessionId, Uint8Array.of(3))
  sessions.get(activeSessionId)?.terminal.focus()
  setNotice(sent ? 'Sent Ctrl+C to the active shell.' : 'The server is offline. Wait for reconnection.',
    sent ? 'neutral' : 'error')
})
new ResizeObserver(() => {
  const session = sessions.get(activeSessionId)
  if (session) requestAnimationFrame(() => fitSession(session))
}).observe(terminalsElement)
setInterval(() => { if (online) send({ type: 'list_devices' }) }, 5000)
renderDevices([])
connect()
