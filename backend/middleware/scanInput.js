export function validateScanInput(req, res, next) {
  const body = req.body
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'A JSON scan object is required' })
  }
  for (const field of ['url', 'target', 'message', 'content', 'body', 'sender', 'subject', 'fileName', 'name', 'mimeType', 'type', 'sha256', 'source']) {
    const value = body[field]
    if (value !== undefined && (typeof value !== 'string' || value.length > 200 * 1024)) {
      return res.status(400).json({ error: `${field} must be text no longer than 200 KB of characters` })
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
  return next()
}
