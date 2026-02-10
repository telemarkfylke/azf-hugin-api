const { app } = require('@azure/functions')
const { logger } = require('@vtfk/logger')
const validateToken = require('../lib/validateToken')

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

    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), timeoutMs)

    try {
      logger('info', ['localLlm', `Proxying to ${baseUrl}/prod/api/generate`, `model=${model}`])

      const ollamaResponse = await fetch(`${baseUrl}/prod/api/generate`, {
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
          jsonBody: { error: `Ollama error: ${errorBody}` }
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
          jsonBody: { error: `Request to on-prem Ollama timed out after ${timeoutMs}ms` }
        }
      }

      logger('error', ['localLlm', 'Failed to reach on-prem Ollama:', error.message])
      return {
        status: 502,
        jsonBody: { error: `Failed to reach on-prem Ollama: ${error.message}` }
      }
    }
  }
})
