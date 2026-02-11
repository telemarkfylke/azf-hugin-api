const { app } = require('@azure/functions')
const { logger } = require('@vtfk/logger')
const dns = require('dns')
const validateToken = require('../lib/validateToken')

function extractCauseChain (error, depth = 0) {
  if (!error.cause || depth >= 3) return undefined
  const cause = error.cause
  const result = {
    message: cause.message,
    code: cause.code,
    errno: cause.errno,
    syscall: cause.syscall,
    address: cause.address,
    port: cause.port
  }
  const nested = extractCauseChain(cause, depth + 1)
  if (nested) result.cause = nested
  return result
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

    // Pre-flight DNS check
    let dnsResult
    try {
      const hostname = new URL(baseUrl).hostname
      const { address, family } = await dns.promises.lookup(hostname)
      dnsResult = { hostname, address, family }
    } catch (dnsError) {
      dnsResult = { error: dnsError.message, code: dnsError.code }
    }

    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), timeoutMs)
    const startTime = Date.now()

    try {
      logger('info', ['localLlm', `Proxying to ${targetUrl}`, `model=${model}`])

      const ollamaResponse = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Host: hostHeader
        },
        body: JSON.stringify({ model, prompt, stream }),
        signal: controller.signal
      })

      clearTimeout(timeout)

      if (!ollamaResponse.ok) {
        const errorBody = await ollamaResponse.text()
        logger('error', ['localLlm', `Ollama returned ${ollamaResponse.status}:`, errorBody])
        return {
          status: ollamaResponse.status,
          jsonBody: {
            error: `Ollama error: ${errorBody}`,
            diagnostics: {
              timestamp: new Date().toISOString(),
              elapsedMs: Date.now() - startTime,
              targetUrl,
              hostHeader,
              dns: dnsResult,
              ollamaStatus: ollamaResponse.status,
              ollamaStatusText: ollamaResponse.statusText,
              ollamaHeaders: Object.fromEntries(ollamaResponse.headers.entries())
            }
          }
        }
      }

      const data = await ollamaResponse.json()
      logger('info', ['localLlm', 'Success'])
      return { jsonBody: data }
    } catch (error) {
      clearTimeout(timeout)

      if (error.name === 'AbortError') {
        logger('error', ['localLlm', `Request timed out after ${timeoutMs}ms`])
        return {
          status: 504,
          jsonBody: {
            error: `Request to on-prem Ollama timed out after ${timeoutMs}ms`,
            diagnostics: {
              timestamp: new Date().toISOString(),
              elapsedMs: Date.now() - startTime,
              targetUrl,
              hostHeader,
              timeoutMs,
              dns: dnsResult
            }
          }
        }
      }

      logger('error', ['localLlm', 'Failed to reach on-prem Ollama:', error.message])
      return {
        status: 418,
        jsonBody: {
          error: `Failed to reach on-prem Ollama: ${error.message}`,
          diagnostics: {
            timestamp: new Date().toISOString(),
            elapsedMs: Date.now() - startTime,
            targetUrl,
            hostHeader,
            timeoutMs,
            dns: dnsResult,
            error: {
              message: error.message,
              code: error.code,
              type: error.type,
              errno: error.errno,
              syscall: error.syscall,
              cause: extractCauseChain(error)
            }
          }
        }
      }
    }
  }
})
