export function Panel({ children, className = '' }) {
  return (
    <section
      className={`rounded-lg border border-emerald-100 bg-white p-4 shadow-[0_12px_30px_rgba(15,118,110,0.08)] dark:border-slate-700 dark:bg-slate-800/85 dark:shadow-none ${className}`}
    >
      {children}
    </section>
  )
}
