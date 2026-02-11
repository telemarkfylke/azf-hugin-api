const { app } = require('@azure/functions')
const { logger } = require('@vtfk/logger')
const dns = require('dns')
const http = require('http')
const https = require('https')
const net = require('net')
const os = require('os')
const validateToken = require('../lib/validateToken')

function extractCauseChain (error, depth = 0) {
  if (!error || !error.cause || depth >= 5) return undefined
  const cause = error.cause
  const result = {
    message: cause.message,
    name: cause.name,
    code: cause.code,
    errno: cause.errno,
    syscall: cause.syscall,
    address: cause.address,
    port: cause.port,
    hostname: cause.hostname
  }
  const nested = extractCauseChain(cause, depth + 1)
  if (nested) result.cause = nested
  return result
}

/**
 * Runs a single diagnostic step with timing and error capture
 */
async function runDiagnostic (name, fn) {
  const start = Date.now()
  try {
    const result = await fn()
    return { name, ok: true, elapsedMs: Date.now() - start, result }
  } catch (error) {
    return {
      name,
      ok: false,
      elapsedMs: Date.now() - start,
      error: {
        message: error.message,
        code: error.code,
        errno: error.errno,
        syscall: error.syscall
      }
    }
  }
}

/**
 * Comprehensive DNS diagnostics for a hostname
 */
async function dnsFullDiagnostics (hostname) {
  const results = await Promise.all([
    // Standard lookup (uses OS resolver, respects /etc/hosts, hybrid connection DNS)
    runDiagnostic('dns.lookup', () => dns.promises.lookup(hostname, { all: true, verbatim: true })),
    // lookup with hints
    runDiagnostic('dns.lookup_v4', () => dns.promises.lookup(hostname, { family: 4 })),
    runDiagnostic('dns.lookup_v6', () => dns.promises.lookup(hostname, { family: 6 })),
    // DNS resolve (bypasses OS resolver, goes directly to DNS servers)
    runDiagnostic('dns.resolve', () => dns.promises.resolve(hostname)),
    runDiagnostic('dns.resolve4', () => dns.promises.resolve4(hostname, { ttl: true })),
    runDiagnostic('dns.resolve6', () => dns.promises.resolve6(hostname, { ttl: true })),
    runDiagnostic('dns.resolveCname', () => dns.promises.resolveCname(hostname)),
    runDiagnostic('dns.resolveAny', () => dns.promises.resolveAny(hostname)),
    runDiagnostic('dns.resolveSrv', () => dns.promises.resolveSrv(hostname)),
    runDiagnostic('dns.resolveMx', () => dns.promises.resolveMx(hostname)),
    runDiagnostic('dns.resolveNs', () => dns.promises.resolveNs(hostname)),
    runDiagnostic('dns.resolveSoa', () => dns.promises.resolveSoa(hostname)),
    runDiagnostic('dns.resolveTxt', () => dns.promises.resolveTxt(hostname))
  ])

  // Also try reverse lookup if we got an IP
  const lookupResult = results.find(r => r.name === 'dns.lookup' && r.ok)
  if (lookupResult && lookupResult.result && lookupResult.result.length > 0) {
    const ip = lookupResult.result[0].address
    const reverse = await runDiagnostic('dns.reverse', () => dns.promises.reverse(ip))
    results.push(reverse)
  }

  return results
}

/**
 * TCP socket connectivity test — checks if we can establish a raw TCP connection
 */
function tcpConnectivityTest (host, port, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const start = Date.now()
    const socket = new net.Socket()
    const result = { host, port, timeoutMs }

    socket.setTimeout(timeoutMs)

    socket.on('connect', () => {
      result.ok = true
      result.elapsedMs = Date.now() - start
      result.localAddress = socket.localAddress
      result.localPort = socket.localPort
      result.remoteAddress = socket.remoteAddress
      result.remotePort = socket.remotePort
      result.remoteFamily = socket.remoteFamily
      socket.destroy()
      resolve(result)
    })

    socket.on('timeout', () => {
      result.ok = false
      result.elapsedMs = Date.now() - start
      result.error = 'TCP connection timed out'
      socket.destroy()
      resolve(result)
    })

    socket.on('error', (err) => {
      result.ok = false
      result.elapsedMs = Date.now() - start
      result.error = {
        message: err.message,
        code: err.code,
        errno: err.errno,
        syscall: err.syscall,
        address: err.address,
        port: err.port
      }
      socket.destroy()
      resolve(result)
    })

    socket.connect(port, host)
  })
}

/**
 * HTTP reachability probe (HEAD + GET fallback) — tests the HTTP layer
 */
async function httpProbe (url, hostHeader, timeoutMs = 10000) {
  const results = []

  for (const method of ['HEAD', 'GET']) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    const start = Date.now()
    try {
      const resp = await fetch(url, {
        method,
        headers: { Host: hostHeader },
        signal: controller.signal
      })
      clearTimeout(timer)
      const body = method === 'GET' ? await resp.text().catch(() => '<read error>') : null
      results.push({
        method,
        ok: true,
        elapsedMs: Date.now() - start,
        status: resp.status,
        statusText: resp.statusText,
        headers: Object.fromEntries(resp.headers.entries()),
        bodyPreview: body ? body.substring(0, 500) : null
      })
      break // If HEAD works, skip GET; if GET works, we're done
    } catch (error) {
      clearTimeout(timer)
      results.push({
        method,
        ok: false,
        elapsedMs: Date.now() - start,
        error: {
          name: error.name,
          message: error.message,
          code: error.code,
          type: error.type,
          cause: extractCauseChain(error)
        }
      })
    }
  }

  return results
}

/**
 * Collect environment and runtime info relevant to Hybrid Connection debugging
 */
function collectEnvironmentInfo () {
  const envKeys = [
    'OLLAMA_BASE_URL', 'OLLAMA_HOST_HEADER', 'OLLAMA_TIMEOUT_MS',
    'WEBSITE_SITE_NAME', 'WEBSITE_INSTANCE_ID', 'WEBSITE_HOSTNAME',
    'WEBSITE_RESOURCE_GROUP', 'WEBSITE_OWNER_NAME',
    'AZURE_FUNCTIONS_ENVIRONMENT', 'FUNCTIONS_WORKER_RUNTIME',
    'WEBSITE_SKU', 'WEBSITE_NODE_DEFAULT_VERSION',
    // Hybrid Connection specific env vars — only expose counts, not connection strings
    'WEBSITE_RELAY_CLOSEDCONNECTIONS',
    'WEBSITE_RELAY_OPENCONNECTIONS',
    // Networking
    'WEBSITE_VNET_ROUTE_ALL', 'WEBSITE_DNS_SERVER', 'WEBSITE_DNS_ALT_SERVER',
    'WEBSITE_PRIVATE_IP', 'WEBSITE_PRIVATE_PORTS',
    'appName'
  ]
  const env = {}
  for (const key of envKeys) {
    if (process.env[key] !== undefined) {
      env[key] = process.env[key]
    }
  }

  // Proxy vars may contain credentials — only expose whether they are set
  for (const proxyKey of ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy']) {
    if (process.env[proxyKey] !== undefined) {
      env[proxyKey] = '<set>'
    }
  }

  // WEBSITE_RELAYS may contain SAS keys — only indicate presence and extract hostnames
  if (process.env.WEBSITE_RELAYS) {
    env.WEBSITE_RELAYS_SET = true
    const sbMatches = process.env.WEBSITE_RELAYS.match(/([a-zA-Z0-9-]+\.servicebus\.windows\.net)/g)
    env.WEBSITE_RELAYS_HOSTNAMES = sbMatches || 'no servicebus hostnames found'
  }

  // Also grab env var NAMES (not values) that relate to hybrid/relay/networking
  // Only expose names to avoid leaking secrets like connection strings or SAS keys
  const hybridRelatedKeys = Object.keys(process.env)
    .filter(key => /relay|hybrid|servicebus|vnet|network/i.test(key))

  return {
    env,
    hybridRelatedEnvKeys: hybridRelatedKeys.length > 0 ? hybridRelatedKeys : 'none found',
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    pid: process.pid,
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    cwd: process.cwd()
  }
}

/**
 * Collect network interface info from the function app host
 */
function collectNetworkInterfaces () {
  const interfaces = os.networkInterfaces()
  const result = {}
  for (const [name, addrs] of Object.entries(interfaces)) {
    result[name] = addrs.map(a => ({
      address: a.address,
      netmask: a.netmask,
      family: a.family,
      internal: a.internal,
      cidr: a.cidr
    }))
  }
  return result
}

/**
 * Perform DNS diagnostics on the Azure Relay / Service Bus endpoint
 * Azure Hybrid Connections route through *.servicebus.windows.net
 */
async function relayEndpointDiagnostics () {
  // Try to discover the relay namespace from env (don't expose raw value — may contain SAS keys)
  const relayInfo = process.env.WEBSITE_RELAYS
  const results = { relayEnvSet: !!relayInfo }

  // Standard Azure Relay endpoints to probe
  const relayHostnames = new Set()

  // Parse WEBSITE_RELAYS if available (format: endpoint1,endpoint2,...)
  if (relayInfo) {
    try {
      // WEBSITE_RELAYS can be JSON or comma-separated
      const parsed = relayInfo.startsWith('[') ? JSON.parse(relayInfo) : relayInfo.split(',')
      for (const entry of parsed) {
        const str = typeof entry === 'string' ? entry : JSON.stringify(entry)
        const sbMatch = str.match(/([a-zA-Z0-9-]+\.servicebus\.windows\.net)/g)
        if (sbMatch) sbMatch.forEach(h => relayHostnames.add(h))
      }
    } catch {
      results.relayParseError = 'Could not parse WEBSITE_RELAYS'
    }
  }

  if (relayHostnames.size === 0) {
    results.note = 'No relay hostnames discovered from environment. Add known relay hostname to WEBSITE_RELAYS or check Azure portal.'
  }

  results.endpoints = {}
  for (const hostname of relayHostnames) {
    results.endpoints[hostname] = await Promise.all([
      runDiagnostic('dns.lookup', () => dns.promises.lookup(hostname, { all: true })),
      runDiagnostic('dns.resolve4', () => dns.promises.resolve4(hostname, { ttl: true })),
      runDiagnostic('dns.resolveCname', () => dns.promises.resolveCname(hostname)),
      runDiagnostic('tcp_443', () => tcpConnectivityTest(hostname, 443, 5000)),
      runDiagnostic('tcp_5671', () => tcpConnectivityTest(hostname, 5671, 5000)),
      runDiagnostic('https_probe', async () => {
        const ctrl = new AbortController()
        const t = setTimeout(() => ctrl.abort(), 5000)
        try {
          const r = await fetch(`https://${hostname}`, { signal: ctrl.signal })
          clearTimeout(t)
          return { status: r.status, statusText: r.statusText, headers: Object.fromEntries(r.headers.entries()) }
        } catch (e) {
          clearTimeout(t)
          throw e
        }
      })
    ])
  }

  return results
}

/**
 * Run the full diagnostics suite and return all results
 */
async function runFullDiagnostics (baseUrl, hostHeader, targetUrl) {
  const diagStart = Date.now()
  const parsedUrl = new URL(baseUrl)
  const hostname = parsedUrl.hostname
  const port = parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80)

  // Run diagnostics in parallel where possible
  const [
    dnsResults,
    tcpResult,
    httpResults,
    relayResults,
    dnsServers
  ] = await Promise.all([
    dnsFullDiagnostics(hostname),
    tcpConnectivityTest(hostname, parseInt(port, 10), 5000),
    httpProbe(targetUrl, hostHeader, 10000),
    relayEndpointDiagnostics(),
    runDiagnostic('dns.getServers', () => Promise.resolve(dns.getServers()))
  ])

  // Also test connectivity to well-known endpoints to see if outbound internet works
  const [googleDns, azureDns] = await Promise.all([
    runDiagnostic('external_dns_google', () => {
      const resolver = new dns.Resolver()
      resolver.setServers(['8.8.8.8'])
      return new Promise((resolve, reject) => {
        resolver.resolve4('www.google.com', (err, addresses) => {
          if (err) reject(err)
          else resolve(addresses)
        })
      })
    }),
    runDiagnostic('external_dns_azure', () => {
      const resolver = new dns.Resolver()
      resolver.setServers(['168.63.129.16'])
      return new Promise((resolve, reject) => {
        resolver.resolve4('management.azure.com', (err, addresses) => {
          if (err) reject(err)
          else resolve(addresses)
        })
      })
    })
  ])

  return {
    diagnosticsTimestamp: new Date().toISOString(),
    diagnosticsTotalMs: Date.now() - diagStart,
    target: {
      baseUrl,
      targetUrl,
      hostname,
      port,
      hostHeader,
      protocol: parsedUrl.protocol
    },
    dnsServers: dnsServers,
    dns: dnsResults,
    tcp: tcpResult,
    http: httpResults,
    externalConnectivity: {
      googleDns,
      azureDns
    },
    azureRelay: relayResults,
    environment: collectEnvironmentInfo(),
    networkInterfaces: collectNetworkInterfaces(),
    os: {
      hostname: os.hostname(),
      type: os.type(),
      platform: os.platform(),
      release: os.release(),
      arch: os.arch(),
      totalMemory: os.totalmem(),
      freeMemory: os.freemem(),
      cpus: os.cpus().length,
      uptime: os.uptime()
    }
  }
}

/**
 * HTTP request using Node's http/https modules — more tolerant of Azure Relay framing quirks
 * than native fetch (undici), which can throw HPE_INVALID_CONSTANT through hybrid connections.
 */
function robustRequest (url, { method = 'POST', headers = {}, body, timeoutMs = 120000, signal } = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url)
    const transport = parsed.protocol === 'https:' ? https : http
    const reqHeaders = {
      ...headers,
      Connection: 'close' // Avoid keep-alive issues through Azure Relay
    }
    if (body) {
      reqHeaders['Content-Length'] = Buffer.byteLength(body)
    }

    const req = transport.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers: reqHeaders,
      // Disable connection reuse — each request gets a fresh socket through the relay
      agent: false,
      // Azure Hybrid Connection relay can return responses that don't strictly
      // conform to HTTP/1.1 framing — use the lenient parser to avoid HPE_INVALID_CONSTANT
      insecureHTTPParser: true
    }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () => {
        const rawBody = Buffer.concat(chunks).toString('utf-8')
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          statusText: res.statusMessage,
          headers: res.headers,
          text: () => Promise.resolve(rawBody),
          json: () => Promise.resolve(JSON.parse(rawBody))
        })
      })
      res.on('error', reject)
    })

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`))
    })

    req.on('error', (err) => {
      if (signal && signal.aborted) {
        const abortErr = new Error('The operation was aborted')
        abortErr.name = 'AbortError'
        reject(abortErr)
      } else {
        reject(err)
      }
    })

    if (signal) {
      if (signal.aborted) {
        req.destroy()
        const abortErr = new Error('The operation was aborted')
        abortErr.name = 'AbortError'
        reject(abortErr)
        return
      }
      signal.addEventListener('abort', () => {
        req.destroy()
        const abortErr = new Error('The operation was aborted')
        abortErr.name = 'AbortError'
        reject(abortErr)
      }, { once: true })
    }

    if (body) {
      req.write(body)
    }
    req.end()
  })
}

app.http('localLlm', {
  methods: ['POST'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    // Validate token
    try {
      const accesstoken = request.headers.get('Authorization')
      await validateToken(accesstoken, { role: [`${process.env.appName}.basic`, `${process.env.appName}.admin`] })
    } catch (error) {
      logger('error', ['localLlm', 'Error validating token:', error])
      return {
        status: 401,
        jsonBody: { error: error.response?.data || error?.stack || error.message }
      }
    }

    // Parse and validate request body
    let params
    try {
      params = JSON.parse(await request.text())
    } catch (error) {
      logger('error', ['localLlm', 'Invalid JSON in request body:', error.message])
      return {
        status: 400,
        jsonBody: { error: 'Invalid JSON in request body' }
      }
    }

    const { model, prompt, stream = false } = params

    if (!model || typeof model !== 'string') {
      return {
        status: 400,
        jsonBody: { error: 'Missing or invalid "model" — must be a non-empty string' }
      }
    }
    if (!prompt || typeof prompt !== 'string') {
      return {
        status: 400,
        jsonBody: { error: 'Missing or invalid "prompt" — must be a non-empty string' }
      }
    }

    // Proxy request to on-prem Ollama via Hybrid Connection
    const baseUrl = process.env.OLLAMA_BASE_URL || 'http://kiserver:1337'
    const hostHeader = process.env.OLLAMA_HOST_HEADER || 'localhost'
    const timeoutMs = parseInt(process.env.OLLAMA_TIMEOUT_MS, 10) || 120000
    const targetUrl = `${baseUrl}/prod/api/generate`

    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), timeoutMs)
    const startTime = Date.now()

    try {
      logger('info', ['localLlm', `Proxying to ${targetUrl}`, `model=${model}`, 'using http/https module (not fetch)'])

      const ollamaResponse = await robustRequest(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Host: hostHeader
        },
        body: JSON.stringify({ model, prompt, stream }),
        timeoutMs,
        signal: controller.signal
      })

      clearTimeout(timeout)

      if (!ollamaResponse.ok) {
        const errorBody = await ollamaResponse.text()
        logger('error', ['localLlm', `Ollama returned ${ollamaResponse.status}:`, errorBody])
        const diagnostics = await runFullDiagnostics(baseUrl, hostHeader, targetUrl)
        return {
          status: ollamaResponse.status,
          jsonBody: {
            error: `Ollama error: ${errorBody}`,
            requestDiagnostics: {
              elapsedMs: Date.now() - startTime,
              ollamaStatus: ollamaResponse.status,
              ollamaStatusText: ollamaResponse.statusText,
              ollamaHeaders: ollamaResponse.headers
            },
            diagnostics
          }
        }
      }

      const data = await ollamaResponse.json()
      logger('info', ['localLlm', 'Success'])
      return { jsonBody: data }
    } catch (error) {
      clearTimeout(timeout)
      const diagnostics = await runFullDiagnostics(baseUrl, hostHeader, targetUrl)

      if (error.name === 'AbortError') {
        logger('error', ['localLlm', `Request timed out after ${timeoutMs}ms`])
        return {
          status: 504,
          jsonBody: {
            error: `Request to on-prem Ollama timed out after ${timeoutMs}ms`,
            requestDiagnostics: {
              elapsedMs: Date.now() - startTime,
              timeoutMs
            },
            diagnostics
          }
        }
      }

      logger('error', ['localLlm', 'Failed to reach on-prem Ollama:', error.message])
      return {
        status: 418,
        jsonBody: {
          error: `Failed to reach on-prem Ollama: ${error.message}`,
          requestDiagnostics: {
            elapsedMs: Date.now() - startTime,
            timeoutMs,
            error: {
              name: error.name,
              message: error.message,
              code: error.code,
              type: error.type,
              errno: error.errno,
              syscall: error.syscall,
              cause: extractCauseChain(error)
            }
          },
          diagnostics
        }
      }
    }
  }
})
