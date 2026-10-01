// Shared by production controllers and evaluation. This module accepts inputs,
// never labels, and has no persistence, mail or administrative review side effects.
import { scanUrl } from './urlScanner.js'
import { scanMessage, extractLinks } from './messageScanner.js'
import { analyzeEmail } from './emailAnalyzer.js'
import { scanFile } from './fileScanner.js'
import { enrichUrlAnalysis } from './threatIntel.js'
import { enrichPageInspection, enrichPageSnapshot } from './pageInspector.js'
import { enrichContentLinks } from './linkReputation.js'
import { enrichEmailAuthentication } from './emailAuthentication.js'

export async function detectUrl(target, { pageSnapshot = null, preview = false } = {}) {
  const reputation = await enrichUrlAnalysis(target, scanUrl(target))
  if (preview) return reputation
  return enrichPageSnapshot(pageSnapshot, await enrichPageInspection(target, reputation))
}

export const detectMessage = (content) => enrichContentLinks(content, scanMessage(content))

export async function detectEmail(input) {
  const { sender, subject = '', body = '', rawEmail = '', smtpClientIp = '', smtpHelo = '', envelopeFrom = '' } = input
  const analysis = await enrichContentLinks(`${subject}\n${body}`.trim(), analyzeEmail({ sender, subject, body }))
  return enrichEmailAuthentication({ rawEmail, smtpClientIp, smtpHelo, envelopeFrom }, analysis)
}

export async function detectFile(input) {
  const analysis = await scanFile(input)
  return extractLinks(input.content ?? '').length ? enrichContentLinks(input.content, analysis) : analysis
}

export const productionDetectors = Object.freeze({ url: detectUrl, message: detectMessage, email: detectEmail, file: detectFile })
export const localDetectors = Object.freeze({ url: scanUrl, message: scanMessage, email: analyzeEmail })
