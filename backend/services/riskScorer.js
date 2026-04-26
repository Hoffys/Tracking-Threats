export function getRiskFromScore(score) {
  if (score >= 80) return { status: 'Safe', risk: 'low', action: 'Allowed' }
  if (score >= 50) return { status: 'Suspicious', risk: 'medium', action: 'Review' }
  return { status: 'Dangerous', risk: 'critical', action: 'Blocked' }
}

export function clampScore(score) {
  return Math.max(0, Math.min(100, score))
}

export function scoreWarnings(warnings) {
  return clampScore(
    100 - warnings.reduce((total, warning) => total + warning.deduction, 0),
  )
}

export function addWarning(warnings, condition, label, deduction) {
  if (condition) {
    warnings.push({ label, deduction })
  }
}

export function recommendationsFor(status) {
  const recommendations = {
    Safe: [
      'Proceed with normal caution.',
      'Continue monitoring for unusual sender or domain behavior.',
    ],
    Suspicious: [
      'Verify the sender or domain through a trusted channel.',
      'Do not enter credentials until the request is confirmed legitimate.',
    ],
    Dangerous: [
      'Block the threat immediately.',
      'Quarantine the content and report it to security.',
      'Verify any account or payment request using an official website or phone number.',
    ],
  }

  return recommendations[status] ?? recommendations.Suspicious
}
