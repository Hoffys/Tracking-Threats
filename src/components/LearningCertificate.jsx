import { useState } from 'react'
import { createPortal } from 'react-dom'
import { Award, Download, Printer } from 'lucide-react'
import './LearningCertificate.css'

export function LearningCertificate({ score, total, moduleCount }) {
  const [name, setName] = useState('')
  const [completedAt] = useState(() => new Date())
  const [downloadError, setDownloadError] = useState('')
  const learnerName = name.trim()
  const completionDate = completedAt.toLocaleDateString(undefined, {
    year: 'numeric', month: 'long', day: 'numeric',
  })

  const downloadCertificate = () => {
    if (!learnerName) return
    setDownloadError('')
    try {
      const canvas = document.createElement('canvas')
      canvas.width = 1600
      canvas.height = 1130
      const context = canvas.getContext('2d')
      if (!context) throw new Error('Canvas unavailable')
      context.fillStyle = '#ffffff'
      context.fillRect(0, 0, canvas.width, canvas.height)
      context.strokeStyle = '#047857'
      context.lineWidth = 5
      context.strokeRect(40, 40, 1520, 1050)
      context.lineWidth = 2
      context.strokeRect(55, 55, 1490, 1020)
      context.fillStyle = '#163b32'
      context.textAlign = 'center'
      const line = (text, y, size = 28, bold = false) => {
        context.font = `${bold ? 'bold ' : ''}${size}px Georgia, serif`
        context.fillText(text, 800, y)
      }
      line('Tracking Threats', 150, 38, true)
      line('SECURITY LEARNING CENTER', 205, 22)
      line('Certificate of Completion', 315, 66, true)
      line('This certificate is presented to', 395)
      let nameSize = 60
      do {
        context.font = `bold ${nameSize}px Georgia, serif`
        if (context.measureText(learnerName).width <= 1380) break
        nameSize -= 1
      } while (nameSize > 16)
      line(learnerName, 495, nameSize, true)
      context.beginPath()
      context.moveTo(180, 525)
      context.lineTo(1420, 525)
      context.stroke()
      line('for completing the', 590)
      line('Beginner Security Awareness', 660, 44, true)
      line(`All ${moduleCount} Beginner modules and the Scenario Trainer test completed.`, 725, 26)
      line(`Quiz score: ${score} / ${total}`, 825, 30, true)
      line(`Completed on ${completionDate}`, 885, 28)
      line('Tracking Threats - Learning Modules', 1005, 24)
      canvas.toBlob((blob) => {
        if (!blob) { setDownloadError('Download unavailable. Please use Print / Save as PDF.'); return }
        const url = URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = 'tracking-threats-beginner-certificate.png'
        document.body.appendChild(link)
        link.click()
        link.remove()
        window.setTimeout(() => URL.revokeObjectURL(url), 10000)
      }, 'image/png')
    } catch {
      setDownloadError('Download unavailable. Please use Print / Save as PDF.')
    }
  }

  const certificate = (
    <article className="learning-certificate" aria-label="Certificate preview">
      <div className="learning-certificate-brand"><Award size={32} aria-hidden="true" /> Tracking Threats</div>
      <p className="learning-certificate-eyebrow">Security learning center</p>
      <h3>Certificate of Completion</h3>
      <p>This certificate is presented to</p>
      <p className="learning-certificate-name">{learnerName || 'Your name'}</p>
      <p>for completing the</p>
      <h4>Beginner Security Awareness</h4>
      <p>All {moduleCount} Beginner modules and the Scenario Trainer test completed.</p>
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
        <Award size={22} aria-hidden="true" /> Your Beginner certificate is ready!
      </h3>
      <p className="mt-2 text-sm text-slate-600 dark:text-slate-300" role="status">
        You completed all {moduleCount} Beginner modules and answered all {total} test questions. Add your name to download or print your certificate.
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
        <button type="button" onClick={downloadCertificate} disabled={!learnerName} className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-3 text-sm font-semibold text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-50">
          <Download size={18} aria-hidden="true" /> Download certificate (PNG)
        </button>
        {downloadError && <p role="alert" className="mt-2 text-sm text-rose-600 dark:text-rose-300">{downloadError}</p>}
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
