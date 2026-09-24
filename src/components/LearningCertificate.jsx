import { useState } from 'react'
import { createPortal } from 'react-dom'
import { Award, Printer } from 'lucide-react'
import './LearningCertificate.css'

export function LearningCertificate({ score, total }) {
  const [name, setName] = useState('')
  const [completedAt] = useState(() => new Date())
  const learnerName = name.trim()
  const completionDate = completedAt.toLocaleDateString(undefined, {
    year: 'numeric', month: 'long', day: 'numeric',
  })

  const certificate = (
    <article className="learning-certificate" aria-label="Certificate preview">
      <div className="learning-certificate-brand"><Award size={32} aria-hidden="true" /> Tracking Threats</div>
      <p className="learning-certificate-eyebrow">Security learning center</p>
      <h3>Certificate of Completion</h3>
      <p>This certificate is presented to</p>
      <p className="learning-certificate-name">{learnerName || 'Your name'}</p>
      <p>for completing the</p>
      <h4>Security Awareness Scenario Trainer</h4>
      <p>Practice in recognizing phishing, deceptive links, and unsafe attachments.</p>
      <div className="learning-certificate-details">
        <div><strong>{score} / {total}</strong><span>Quiz score</span></div>
        <div><strong>{completionDate}</strong><span>Completion date</span></div>
      </div>
      <p className="learning-certificate-footer">Tracking Threats · Learning Modules</p>
    </article>
  )

  return (
    <section className="mt-4 rounded-lg border border-emerald-300 bg-emerald-50 p-4 dark:border-emerald-700 dark:bg-emerald-950/40" aria-labelledby="certificate-title">
      <h3 id="certificate-title" className="flex items-center gap-2 text-lg font-semibold text-emerald-900 dark:text-emerald-200">
        <Award size={22} aria-hidden="true" /> Your certificate is ready!
      </h3>
      <p className="mt-2 text-sm text-slate-600 dark:text-slate-300" role="status">
        You answered all {total} questions. Add your name to print your certificate or save it as a PDF.
      </p>
      <form className="mt-4" onSubmit={(event) => { event.preventDefault(); if (learnerName) window.print() }}>
        <label htmlFor="certificate-name" className="block text-sm font-semibold">Name on certificate</label>
        <input
          id="certificate-name"
          autoComplete="name"
          required
          maxLength={80}
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="Enter your full name"
          className="mt-2 w-full rounded-lg border border-emerald-200 bg-white px-3 py-2 text-slate-950 outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-500 dark:border-slate-600 dark:bg-slate-900 dark:text-white"
        />
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">Your name is used only for this certificate and is not sent to the server.</p>
        <div className="mt-4">{certificate}</div>
        <button type="submit" disabled={!learnerName} className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-3 text-sm font-semibold text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-50">
          <Printer size={18} aria-hidden="true" /> Print / Save as PDF
        </button>
      </form>
      {learnerName && createPortal(
        <div className="learning-certificate-print" aria-hidden="true">{certificate}</div>,
        document.body,
      )}
    </section>
  )
}
