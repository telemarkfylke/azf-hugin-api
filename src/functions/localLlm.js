const http = require('http')
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

    const requestHeaders = {
      Host: TARGET_HOST,
      Accept: 'application/json'
    }

    const results = {
      timestamp: new Date().toISOString(),
      target: `http://${ON_PREM_IP}/prod/api/tags`,
      requestHeaders,
      checks: {}
    }

    // Check outbound IP to verify VPN routing is active
    try {
      const ipResponse = await fetch('https://api.ipify.org?format=json')
      const ipData = await ipResponse.json()
      results.checks.outboundPublicIp = ipData.ip
    } catch (error) {
      logger('error', ['localLlm', 'ipify failed', error?.message, error?.cause?.message, error?.cause?.code])
      results.checks.outboundPublicIp = { error: error.message, cause: error?.cause?.message, code: error?.cause?.code }
    }

    // Request Ollama tags through Traefik using http module (fetch silently drops the Host header)
    try {
      const startTime = Date.now()
      const { statusCode, headers: responseHeaders, body } = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: ON_PREM_IP,
          path: '/prod/api/tags',
          method: 'GET',
          headers: requestHeaders,
          timeout: 10000
        }, (res) => {
          const chunks = []
          res.on('data', (chunk) => chunks.push(chunk))
          res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }))
        })
        req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')) })
        req.on('error', reject)
        req.end()
      })

      results.checks.httpStatus = statusCode
      results.checks.latencyMs = Date.now() - startTime
      results.checks.responseHeaders = responseHeaders

      if (statusCode >= 200 && statusCode < 300) {
        results.checks.data = JSON.parse(body)
      } else {
        results.checks.errorBody = body
      }

      logger('info', ['localLlm', `status=${statusCode}`, `latency=${results.checks.latencyMs}ms`])
    } catch (error) {
      logger('error', ['localLlm', 'ollama failed', error?.message, error?.cause?.message, error?.cause?.code])
      results.success = false
      results.error = { message: error.message, cause: error?.cause?.message, code: error?.cause?.code }
    }

    return { jsonBody: results }
  }
})
