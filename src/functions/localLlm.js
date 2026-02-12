const { app } = require('@azure/functions')
const { logger } = require('@vtfk/logger')
const validateToken = require('../lib/validateToken')

const ON_PREM_IP = process.env.ON_PREM_SERVER_IP
const TARGET_HOST = process.env.OLLAMA_HOST_HEADER || 'kiserver'

app.http('localLlm', {
  methods: ['GET'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    // Validate token
    try {
      const accesstoken = request.headers.get('Authorization')
      await validateToken(accesstoken, { role: [`${process.env.appName}.basic`, `${process.env.appName}.admin`] })
    } catch (error) {
      logger('error', ['localLlm', 'Tokenvalidation', error?.message, error?.stack])
      return {
        status: 401,
        jsonBody: { error: error.response?.data || error?.stack || error.message }
      }
    }

    const results = {
      timestamp: new Date().toISOString(),
      target: `http://${ON_PREM_IP}/prod/api/tags`,
      checks: {}
    }

    try {
      // Check outbound IP to verify VPN routing is active
      const ipResponse = await fetch('https://api.ipify.org?format=json')
      const ipData = await ipResponse.json()
      results.checks.outboundPublicIp = ipData.ip

      // Request Ollama tags through Traefik
      const startTime = Date.now()
      const response = await fetch(`http://${ON_PREM_IP}/prod/api/tags`, {
        method: 'GET',
        headers: {
          Host: TARGET_HOST,
          Accept: 'application/json'
        },
        signal: AbortSignal.timeout(10000)
      })

      results.checks.httpStatus = response.status
      results.checks.latencyMs = Date.now() - startTime

      if (response.ok) {
        results.checks.data = await response.json()
      } else {
        results.checks.errorBody = await response.text()
      }

      logger('info', ['localLlm', `status=${response.status}`, `latency=${results.checks.latencyMs}ms`])
    } catch (error) {
      logger('error', ['localLlm', error?.message, error?.stack])
      results.success = false
      results.error = error.message
    }

    return { jsonBody: results }
  }
})
