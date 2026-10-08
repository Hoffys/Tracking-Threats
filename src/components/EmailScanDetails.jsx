const formatAssessment = (assessment) => {
  if (!assessment) return 'Not available'

  const status = assessment.status ?? 'Not checked'
  const score = Number.isFinite(assessment.score)
    ? ` • ${assessment.score}/100`
    : ''

  return `${status}${score}`
}

function DetailItem({ label, value }) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-wide text-slate-400">
        {label}
      </dt>
      <dd className="mt-1 break-words text-sm font-medium text-slate-700 dark:text-slate-200">
        {value}
      </dd>
    </div>
  )
}

export function EmailScanDetails({ scan }) {
  if (scan?.type !== 'Email') return null

  const breakdown = scan.emailBreakdown
  const sender =
    scan.emailDetails?.sender ||
    breakdown?.sender?.domain ||
    'Sender not retained'

  const subject =
    scan.emailDetails?.subject ||
    'Subject not retained for privacy'

  return (
    <div className="mt-4 rounded-lg border border-sky-200 bg-sky-50/60 p-4 dark:border-sky-900 dark:bg-sky-950/20">
      <p className="text-xs font-semibold uppercase tracking-wide text-sky-700 dark:text-sky-300">
        Email details
      </p>

      <dl className="mt-3 grid gap-3 sm:grid-cols-2">
        <DetailItem label="Sender / domain" value={sender} />
        <DetailItem label="Subject" value={subject} />
        <DetailItem
          label="Sender assessment"
          value={formatAssessment(breakdown?.sender)}
        />
        <DetailItem
          label="Message content"
          value={formatAssessment(breakdown?.content)}
        />
        <DetailItem
          label="Embedded links"
          value={formatAssessment(breakdown?.links)}
        />
      </dl>

      <p className="mt-3 text-xs leading-5 text-slate-500 dark:text-slate-400">
        Raw email bodies are not displayed or retained in production.
        Subject availability depends on the configured storage policy.
      </p>
    </div>
  )
}