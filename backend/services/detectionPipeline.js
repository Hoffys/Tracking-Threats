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
import { attachThreatClassification } from './threatClassification.js'

export async function detectUrl(target, { pageSnapshot = null, preview = false } = {}) {
  const reputation = await enrichUrlAnalysis(target, scanUrl(target))
  const analysis = preview
    ? reputation
    : await enrichPageSnapshot(pageSnapshot, await enrichPageInspection(target, reputation))
  return attachThreatClassification('URL', analysis)
}

export const detectMessage = async (content) =>
  attachThreatClassification('Message', await enrichContentLinks(content, scanMessage(content)))

export async function detectEmail(input) {
  const { sender, subject = '', body = '', rawEmail = '', smtpClientIp = '', smtpHelo = '', envelopeFrom = '' } = input
  const analysis = await enrichContentLinks(`${subject}\n${body}`.trim(), analyzeEmail({ sender, subject, body }))
  return attachThreatClassification('Email', await enrichEmailAuthentication({ rawEmail, smtpClientIp, smtpHelo, envelopeFrom }, analysis))
}

export async function detectFile(input) {
  const analysis = await scanFile(input)
  const enriched = extractLinks(input.content ?? '').length ? await enrichContentLinks(input.content, analysis) : analysis
  return attachThreatClassification('File', enriched)
}

export const productionDetectors = Object.freeze({ url: detectUrl, message: detectMessage, email: detectEmail, file: detectFile })
export const localDetectors = Object.freeze({ url: scanUrl, message: scanMessage, email: analyzeEmail })
