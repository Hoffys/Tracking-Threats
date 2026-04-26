import { motion } from 'framer-motion'

export function StatCard({ icon: Icon, label, value, tone = 'slate' }) {
  const tones = {
    slate: {
      icon: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200',
      glow: 'shadow-[0_0_22px_rgba(148,163,184,0.22)]',
      line: 'bg-slate-400',
    },
    teal: {
      icon: 'bg-teal-100 text-teal-700 dark:bg-teal-950 dark:text-teal-200',
      glow: 'shadow-[0_0_26px_rgba(20,184,166,0.28)]',
      line: 'bg-teal-400',
    },
    amber: {
      icon: 'bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-200',
      glow: 'shadow-[0_0_26px_rgba(245,158,11,0.26)]',
      line: 'bg-amber-400',
    },
    rose: {
      icon: 'bg-rose-100 text-rose-700 dark:bg-rose-950 dark:text-rose-200',
      glow: 'shadow-[0_0_26px_rgba(244,63,94,0.25)]',
      line: 'bg-rose-400',
    },
  }
  const activeTone = tones[tone] ?? tones.slate
  const bars = [42, 70, 54, 86, 63, 92, 58]

  return (
    <motion.div
      animate={{ boxShadow: ['0 0 0 rgba(20,184,166,0)', '0 0 22px rgba(20,184,166,0.12)', '0 0 0 rgba(20,184,166,0)'] }}
      transition={{ duration: 2.6, repeat: Infinity, ease: 'easeInOut' }}
      className={`overflow-hidden rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900 ${activeTone.glow}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className={`grid h-10 w-10 place-items-center rounded-lg ${activeTone.icon}`}>
          <Icon size={20} />
        </div>
        <div className="flex h-10 items-end gap-1">
          {bars.map((height, index) => (
            <motion.span
              key={`${label}-${height}-${index}`}
              animate={{ height: [`${Math.max(18, height - 20)}%`, `${height}%`, `${Math.max(24, height - 12)}%`] }}
              transition={{
                duration: 1.35 + index * 0.08,
                repeat: Infinity,
                repeatType: 'mirror',
                ease: 'easeInOut',
              }}
              className={`w-1.5 rounded-full ${activeTone.line} opacity-75 shadow-[0_0_10px_currentColor]`}
            />
          ))}
        </div>
      </div>
      <p className="mt-4 text-2xl font-semibold text-slate-950 dark:text-white">{value}</p>
      <p className="text-sm text-slate-500 dark:text-slate-400">{label}</p>
    </motion.div>
  )
}
