export function validateScanInput(req, res, next) {
  const body = req.body
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'A JSON scan object is required' })
  }
  for (const field of ['url', 'target', 'message', 'content', 'body', 'sender', 'subject', 'fileName', 'name', 'mimeType', 'type', 'sha256', 'source', 'rawEmail', 'smtpClientIp', 'smtpHelo', 'envelopeFrom']) {
    const value = body[field]
    const limit = field === 'rawEmail' ? 400 * 1024 : 200 * 1024
    if (value !== undefined && (typeof value !== 'string' || value.length > limit)) {
      return res.status(400).json({ error: `${field} must be text no longer than ${limit / 1024} KB of characters` })
    }
  }
  if (req.path === '/scan/url') {
    const target = body.url ?? body.target
    try {
      if (!target?.trim() || target.length > 8192) throw new Error()
      const parsed = new URL(target.includes('://') ? target : `https://${target}`)
      if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) throw new Error()
    } catch {
      return res.status(400).json({ error: 'Provide a valid HTTP or HTTPS URL no longer than 8192 characters' })
    }
  }
  if (body.size !== undefined && (!Number.isFinite(Number(body.size)) || Number(body.size) < 0)) {
    return res.status(400).json({ error: 'File size must be a non-negative number' })
  }
  if (body.pageSnapshot !== undefined) {
    const snapshot = body.pageSnapshot
    if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot) || JSON.stringify(snapshot).length > 20 * 1024) {
      return res.status(400).json({ error: 'pageSnapshot must be a JSON object no larger than 20 KB' })
    }
    const numeric = ['passwordFields', 'formCount', 'externalFormActions', 'hiddenFrames']
    if (numeric.some((field) => snapshot[field] !== undefined && (!Number.isInteger(snapshot[field]) || snapshot[field] < 0 || snapshot[field] > 100))) {
      return res.status(400).json({ error: 'pageSnapshot counts must be integers from 0 to 100' })
    }
    if (snapshot.title !== undefined && (typeof snapshot.title !== 'string' || snapshot.title.length > 200)) {
      return res.status(400).json({ error: 'pageSnapshot title must be no longer than 200 characters' })
    }
  }
  return next()
}
