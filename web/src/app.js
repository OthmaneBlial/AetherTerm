import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import './app.css'

const connectionStatus = document.getElementById('connection-status')
const notice = document.getElementById('notice')
const devicesElement = document.getElementById('devices')
const tabsElement = document.getElementById('session-tabs')
const terminalsElement = document.getElementById('terminals')
const emptyElement = document.getElementById('terminal-empty')
const closeButton = document.getElementById('close-session')
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
  if (!session?.ready || !online) return
  for (let offset = 0; offset < bytes.length; offset += 16384) {
    send({ type: 'term_input', sessionId, input: encodedBytes(bytes.subarray(offset, offset + 16384)) })
  }
}

function renderDevices(deviceIds) {
  const nextKey = JSON.stringify([online, deviceIds])
  if (deviceRenderKey === nextKey) return
  deviceRenderKey = nextKey
  devicesElement.replaceChildren()
  if (!deviceIds.length) {
    const empty = document.createElement('p')
    empty.className = 'device-empty'
    empty.textContent = online ? 'No agent is connected. Enroll and start one to continue.' : 'Waiting for the server connection.'
    devicesElement.append(empty)
    return
  }
  for (const deviceId of deviceIds) {
    const button = document.createElement('button')
    button.type = 'button'
    button.className = 'device-button'
    button.innerHTML = '<span class="device-icon" aria-hidden="true">⌁</span><span class="device-copy"><strong></strong><small>ONLINE · OPEN SHELL</small></span><span class="device-arrow" aria-hidden="true">↗</span>'
    button.querySelector('strong').textContent = deviceId
    button.addEventListener('click', () => {
      if (pendingDevice || !online) return
      pendingDevice = deviceId
      if (!send({ type: 'start_session', deviceId })) pendingDevice = null
      else setNotice(`Opening a shell on ${deviceId}…`)
    })
    devicesElement.append(button)
  }
}

function fitSession(session) {
  if (activeSessionId !== session.id) return
  session.fit.fit()
  if (session.ready) {
    send({ type: 'resize', sessionId: session.id, cols: session.terminal.cols, rows: session.terminal.rows })
  }
}

function activateSession(sessionId) {
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
  terminalState.textContent = session ? `${session.deviceId.toUpperCase()} · ${session.ready ? 'SHELL READY' : 'STARTING SHELL'}` : 'NO ACTIVE SESSION'
  if (session) requestAnimationFrame(() => { fitSession(session); session.terminal.focus() })
}

function createSession(id, deviceId) {
  const tab = document.createElement('button')
  tab.type = 'button'
  tab.className = 'session-tab'
  tab.setAttribute('role', 'tab')
  tab.textContent = deviceId
  tab.addEventListener('click', () => activateSession(id))
  tabsElement.append(tab)

  const pane = document.createElement('div')
  pane.className = 'terminal-pane'
  pane.setAttribute('role', 'tabpanel')
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
    renderDevices(message.devices)
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
    if (activeSessionId === session.id) terminalState.textContent = `${session.deviceId.toUpperCase()} · SHELL READY`
    setNotice(`Shell ready on ${session.deviceId}. Type directly in the terminal.`, 'success')
  } else if (message.type === 'term_data') {
    const session = sessions.get(message.sessionId)
    if (session) session.terminal.write(decodedBytes(message.data))
  } else if (message.type === 'session_closed') {
    const session = sessions.get(message.sessionId)
    if (session) setNotice(`Shell closed on ${session.deviceId}.`, 'neutral')
    removeSession(message.sessionId)
  } else if (message.type === 'error') {
    pendingDevice = null
    setNotice(message.message || 'The request failed.', 'error')
  }
}

function connect() {
  clearTimeout(reconnectTimer)
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  socket = new WebSocket(`${protocol}//${window.location.host}/ws`)
  setConnection('Connecting', 'connecting')
  socket.addEventListener('open', () => {
    online = true
    reconnectDelay = 1000
    setConnection('Server connected', 'online')
    setNotice('Choose a connected device to open a shell.', 'success')
    send({ type: 'list_devices' })
  })
  socket.addEventListener('message', handleMessage)
  socket.addEventListener('close', event => {
    online = false
    pendingDevice = null
    for (const id of [...sessions.keys()]) removeSession(id)
    renderDevices([])
    setConnection('Server offline', 'offline')
    if (event.code === 1008) {
      setNotice('Access expired or was revoked. Sign in again.', 'error')
      return
    }
    setNotice('Connection lost. Retrying; previous shells are closed.', 'error')
    reconnectTimer = setTimeout(connect, reconnectDelay)
    reconnectDelay = Math.min(reconnectDelay * 2, 30000)
  })
}

document.getElementById('refresh-devices').addEventListener('click', () => {
  if (!send({ type: 'list_devices' })) setNotice('The server is offline. Wait for reconnection.', 'error')
})
closeButton.addEventListener('click', () => {
  if (activeSessionId) send({ type: 'close_session', sessionId: activeSessionId })
})
new ResizeObserver(() => {
  const session = sessions.get(activeSessionId)
  if (session) requestAnimationFrame(() => fitSession(session))
}).observe(terminalsElement)
setInterval(() => { if (online) send({ type: 'list_devices' }) }, 5000)
renderDevices([])
connect()
