import { useState } from 'react'
import {
  BadgeCheck,
  BookOpenCheck,
  Brain,
  CheckCircle2,
  ChevronRight,
  X,
  FileWarning,
  Globe2,
  GraduationCap,
  KeyRound,
  ListChecks,
  MailWarning,
  RotateCcw,
  Search,
  MessageSquareWarning,
  ShieldCheck,
} from 'lucide-react'
import { Panel } from '../components/Panel'

const modules = [
  {
    title: 'Phishing Basics',
    level: 'Beginner',
    time: '8 min',
    icon: MailWarning,
    summary: 'Learn how fake emails, urgent messages, and spoofed brands trick users.',
    lessons: ['Sender checks', 'Urgency patterns', 'Suspicious attachments'],
    accent: 'text-rose-600 bg-rose-50 dark:bg-rose-950/40 dark:text-rose-300',
  },
  {
    title: 'Email Red Flags',
    level: 'Beginner',
    time: '6 min',
    icon: MailWarning,
    summary: 'Practice spotting suspicious greetings, spelling issues, and unexpected requests.',
    lessons: ['Generic greetings', 'Unusual sender tone', 'Unexpected requests'],
    accent: 'text-rose-600 bg-rose-50 dark:bg-rose-950/40 dark:text-rose-300',
  },
  {
    title: 'Safe URL Checking',
    level: 'Beginner',
    time: '10 min',
    icon: Globe2,
    summary: 'Spot dangerous links before opening them by reading domains and paths.',
    lessons: ['HTTPS limits', 'Lookalike domains', 'Short links'],
    accent: 'text-blue-600 bg-blue-50 dark:bg-blue-950/40 dark:text-blue-300',
  },
  {
    title: 'Message Scam Detection',
    level: 'Beginner',
    time: '7 min',
    icon: MessageSquareWarning,
    summary: 'Identify suspicious SMS, chat, and social messages asking for money or codes.',
    lessons: ['OTP requests', 'Payment pressure', 'Impersonation'],
    accent: 'text-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 dark:text-emerald-300',
  },
  {
    title: 'Safe Browsing Habits',
    level: 'Beginner',
    time: '7 min',
    icon: Globe2,
    summary: 'Build daily habits for checking websites before trusting downloads or forms.',
    lessons: ['Check domains', 'Avoid popups', 'Use trusted bookmarks'],
    accent: 'text-blue-600 bg-blue-50 dark:bg-blue-950/40 dark:text-blue-300',
  },
  {
    title: 'Fake Login Pages',
    level: 'Beginner',
    time: '8 min',
    icon: KeyRound,
    summary: 'Recognize login pages that copy trusted brands to steal usernames and passwords.',
    lessons: ['Check the address bar', 'Avoid copied forms', 'Use official apps'],
    accent: 'text-violet-600 bg-violet-50 dark:bg-violet-950/40 dark:text-violet-300',
  },
  {
    title: 'Password Defense',
    level: 'Intermediate',
    time: '12 min',
    icon: KeyRound,
    summary: 'Use stronger account habits to reduce damage after a phishing attempt.',
    lessons: ['Password managers', 'MFA prompts', 'Credential reset steps'],
    accent: 'text-violet-600 bg-violet-50 dark:bg-violet-950/40 dark:text-violet-300',
  },
  {
    title: 'Multi-Factor Authentication',
    level: 'Intermediate',
    time: '11 min',
    icon: KeyRound,
    summary: 'Understand MFA prompts, backup codes, and suspicious approval requests.',
    lessons: ['Push fatigue', 'Backup codes', 'Authenticator apps'],
    accent: 'text-violet-600 bg-violet-50 dark:bg-violet-950/40 dark:text-violet-300',
  },
  {
    title: 'File & Attachment Safety',
    level: 'Intermediate',
    time: '9 min',
    icon: FileWarning,
    summary: 'Review risky file names, macro-enabled documents, and script attachments.',
    lessons: ['Double extensions', 'Macros', 'Executable files'],
    accent: 'text-amber-600 bg-amber-50 dark:bg-amber-950/40 dark:text-amber-300',
  },
  {
    title: 'Social Engineering Tactics',
    level: 'Intermediate',
    time: '13 min',
    icon: Brain,
    summary: 'Learn how attackers use trust, authority, fear, and rewards to influence decisions.',
    lessons: ['Authority pressure', 'Urgent rewards', 'Trust verification'],
    accent: 'text-cyan-700 bg-cyan-50 dark:bg-cyan-950/40 dark:text-cyan-300',
  },
  {
    title: 'Report Quality',
    level: 'Intermediate',
    time: '10 min',
    icon: BookOpenCheck,
    summary: 'Capture useful evidence so suspicious activity can be reviewed quickly.',
    lessons: ['Save URLs', 'Capture screenshots', 'Write clear context'],
    accent: 'text-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 dark:text-emerald-300',
  },
  {
    title: 'Browser Extension Safety',
    level: 'Intermediate',
    time: '10 min',
    icon: ShieldCheck,
    summary: 'Review permissions and warning signs before installing browser tools.',
    lessons: ['Permission review', 'Trusted sources', 'Extension cleanup'],
    accent: 'text-cyan-700 bg-cyan-50 dark:bg-cyan-950/40 dark:text-cyan-300',
  },
  {
    title: 'Incident Response',
    level: 'Advanced',
    time: '15 min',
    icon: ShieldCheck,
    summary: 'Know what to do after a user clicks a suspicious link or opens a bad file.',
    lessons: ['Containment', 'Evidence capture', 'Reporting'],
    accent: 'text-cyan-700 bg-cyan-50 dark:bg-cyan-950/40 dark:text-cyan-300',
  },
  {
    title: 'Threat Triage',
    level: 'Advanced',
    time: '14 min',
    icon: ShieldCheck,
    summary: 'Prioritize blocked threats by severity, source, and potential business impact.',
    lessons: ['Severity ranking', 'Source review', 'Impact notes'],
    accent: 'text-cyan-700 bg-cyan-50 dark:bg-cyan-950/40 dark:text-cyan-300',
  },
  {
    title: 'Domain Investigation',
    level: 'Advanced',
    time: '16 min',
    icon: Globe2,
    summary: 'Review domain age signals, redirects, and reputation clues before allowing a site.',
    lessons: ['Redirect chains', 'Reputation signals', 'Domain patterns'],
    accent: 'text-blue-600 bg-blue-50 dark:bg-blue-950/40 dark:text-blue-300',
  },
  {
    title: 'Attachment Analysis',
    level: 'Advanced',
    time: '15 min',
    icon: FileWarning,
    summary: 'Evaluate high-risk files using names, hashes, content indicators, and context.',
    lessons: ['Hash checking', 'Script indicators', 'Context review'],
    accent: 'text-amber-600 bg-amber-50 dark:bg-amber-950/40 dark:text-amber-300',
  },
  {
    title: 'Security Coaching',
    level: 'Advanced',
    time: '12 min',
    icon: GraduationCap,
    summary: 'Turn risky events into clear reminders that help users improve safely.',
    lessons: ['Calm feedback', 'Actionable tips', 'Follow-up review'],
    accent: 'text-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 dark:text-emerald-300',
  },
  {
    title: 'Policy & Allowlist Review',
    level: 'Advanced',
    time: '13 min',
    icon: ListChecks,
    summary: 'Decide when a blocked site should stay blocked or be safely allowed.',
    lessons: ['False positive review', 'Allowlist notes', 'Recheck schedule'],
    accent: 'text-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 dark:text-emerald-300',
  },
]

const checklist = [
  'Check the sender address and domain before trusting a message.',
  'Hover or preview links before opening them.',
  'Never share one-time codes, passwords, or recovery links.',
  'Scan files before opening downloads or email attachments.',
  'Report suspicious activity quickly so it can be blocked.',
]

const scenarios = [
  {
    prompt: 'An email says your account will close in 10 minutes unless you sign in.',
    answer: 'High risk',
    choices: ['Safe', 'High risk', 'Needs context'],
    reason: 'Urgency plus login pressure is a common credential-theft pattern.',
  },
  {
    prompt: 'A link says paypal.com.security-check.example.net.',
    answer: 'High risk',
    choices: ['Safe', 'High risk', 'Needs context'],
    reason: 'The real domain is example.net, not paypal.com.',
  },
  {
    prompt: 'A coworker sends an unexpected invoice.pdf.exe attachment.',
    answer: 'High risk',
    choices: ['Safe', 'High risk', 'Needs context'],
    reason: 'Double extensions can hide executable files.',
  },
]

export function Learn({ onNavigate }) {
  const [activeModule, setActiveModule] = useState('')
  const [activeLessonIndex, setActiveLessonIndex] = useState(0)
  const [checkedItems, setCheckedItems] = useState([])
  const [completedModules, setCompletedModules] = useState([])
  const [completionDismissed, setCompletionDismissed] = useState(false)
  const [levelFilter, setLevelFilter] = useState('All')
  const [moduleNotes, setModuleNotes] = useState({})
  const [query, setQuery] = useState('')
  const [scenarioAnswers, setScenarioAnswers] = useState({})
  const selectedModule = modules.find((module) => module.title === activeModule)
  const SelectedIcon = selectedModule?.icon
  const progress = Math.round((completedModules.length / modules.length) * 100)
  const isComplete = progress === 100
  const quizAnswered = Object.keys(scenarioAnswers).length
  const quizScore = scenarios.filter(
    (scenario) => scenarioAnswers[scenario.prompt] === scenario.answer,
  ).length
  const activeLesson = selectedModule?.lessons[activeLessonIndex] ?? selectedModule?.lessons[0]
  const filteredModules = modules.filter((module) => {
    const matchesLevel = levelFilter === 'All' || module.level === levelFilter
    const searchText = `${module.title} ${module.summary} ${module.lessons.join(' ')}`.toLowerCase()
    return matchesLevel && searchText.includes(query.trim().toLowerCase())
  })
  const levels = ['All', 'Beginner', 'Intermediate', 'Advanced']

  const toggleComplete = (title) => {
    setCompletedModules((current) =>
      current.includes(title) ? current.filter((item) => item !== title) : [...current, title],
    )
    setCompletionDismissed(false)
  }

  const selectModule = (title) => {
    setActiveModule(title)
    setActiveLessonIndex(0)
  }

  const chooseScenarioAnswer = (prompt, choice) => {
    setScenarioAnswers((current) => ({ ...current, [prompt]: choice }))
  }

  const toggleChecklistItem = (item) => {
    setCheckedItems((current) =>
      current.includes(item) ? current.filter((entry) => entry !== item) : [...current, item],
    )
  }

  const resetLearn = () => {
    setActiveModule('')
    setActiveLessonIndex(0)
    setCheckedItems([])
    setCompletionDismissed(false)
    setCompletedModules([])
    setLevelFilter('All')
    setModuleNotes({})
    setQuery('')
    setScenarioAnswers({})
  }

  return (
    <div className="space-y-5">
      <section className="rounded-lg border border-emerald-300 bg-emerald-100/80 p-5 shadow-[0_16px_36px_rgba(5,150,105,0.12)] dark:border-emerald-700 dark:bg-emerald-950/35">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex min-w-0 items-center gap-4">
            <span className="grid h-16 w-16 shrink-0 place-items-center rounded-lg bg-emerald-500 text-white shadow-[0_14px_28px_rgba(5,150,105,0.25)]">
              <GraduationCap size={32} />
            </span>
            <div>
              <p className="text-sm font-medium text-emerald-700 dark:text-emerald-300">
                Security learning center
              </p>
              <h1 className="mt-1 text-3xl font-semibold text-slate-950 dark:text-white">
                Learn Modules
              </h1>
              <p className="mt-2 max-w-2xl text-sm text-emerald-800 dark:text-emerald-200">
                Short lessons for recognizing phishing, unsafe links, risky files, and response steps.
              </p>
            </div>
          </div>
          <button
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-emerald-700"
            type="button"
            onClick={() => onNavigate('manual')}
          >
            Practice Scan
            <ChevronRight size={17} />
          </button>
        </div>
        <div className="mt-5">
          <div className="mb-2 flex items-center justify-between text-sm font-medium text-emerald-800 dark:text-emerald-200">
            <span>Learning progress</span>
            <span>{progress}% complete</span>
          </div>
          <div className="h-3 overflow-hidden rounded-full bg-white/70 dark:bg-slate-900/70">
            <div
              className="h-full rounded-full bg-emerald-500 transition-all"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
        {isComplete && !completionDismissed && (
          <div className="mt-4 rounded-lg border border-emerald-400 bg-white/85 p-4 shadow-[0_12px_28px_rgba(5,150,105,0.16)] dark:border-emerald-700 dark:bg-slate-900/80">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="flex gap-3">
                <span className="grid h-11 w-11 shrink-0 place-items-center rounded-lg bg-emerald-500 text-white">
                  <BadgeCheck size={24} />
                </span>
                <div>
                  <h2 className="text-lg font-semibold text-slate-950 dark:text-white">
                    Congratulations, learning complete!
                  </h2>
                  <p className="mt-1 text-sm leading-6 text-emerald-800 dark:text-emerald-200">
                    Reminder: stay alert before clicking links, opening attachments, or sharing
                    passwords and one-time codes. Use Manual Scan whenever something feels unusual.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setCompletionDismissed(true)}
                className="rounded-lg border border-emerald-200 px-3 py-2 text-sm font-semibold text-emerald-800 transition hover:bg-emerald-50 dark:border-slate-700 dark:text-emerald-300 dark:hover:bg-slate-800"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}
        <div className="mt-4 grid gap-3 md:grid-cols-[1fr_auto] md:items-center">
          <div className="relative">
            <Search
              size={17}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-emerald-600"
            />
            <input
              className="w-full rounded-lg border border-emerald-200 bg-white/80 py-3 pl-10 pr-3 text-sm outline-none transition focus:border-emerald-500 dark:border-slate-700 dark:bg-slate-900/70"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search modules, lessons, or skills"
            />
          </div>
          <button
            type="button"
            onClick={resetLearn}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-emerald-300 bg-white/70 px-4 py-3 text-sm font-semibold text-emerald-800 transition hover:bg-white dark:border-slate-700 dark:bg-slate-900/70 dark:text-emerald-300"
          >
            <RotateCcw size={16} />
            Reset Learn
          </button>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {levels.map((level) => (
            <button
              key={level}
              type="button"
              onClick={() => setLevelFilter(level)}
              className={`rounded-full border px-3 py-1.5 text-xs font-semibold transition ${
                levelFilter === level
                  ? 'border-emerald-600 bg-emerald-600 text-white'
                  : 'border-emerald-200 bg-white/70 text-emerald-800 hover:border-emerald-400 dark:border-slate-700 dark:bg-slate-900/70 dark:text-slate-300'
              }`}
            >
              {level}
            </button>
          ))}
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {filteredModules.map((module) => {
          const Icon = module.icon
          const selected = activeModule === module.title
          const completed = completedModules.includes(module.title)
          return (
            <button
              key={module.title}
              type="button"
              onClick={() => selectModule(module.title)}
              className={`rounded-lg text-left transition ${
                selected
                  ? 'ring-2 ring-emerald-500 ring-offset-2 ring-offset-emerald-50 dark:ring-offset-slate-950'
                  : 'hover:-translate-y-0.5'
              }`}
            >
              <Panel className="flex min-h-64 flex-col">
              <div className="flex items-start justify-between gap-3">
                <span className={`grid h-12 w-12 place-items-center rounded-lg ${module.accent}`}>
                  <Icon size={23} />
                </span>
                <span className="rounded-full border border-emerald-100 bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-700 dark:border-slate-700 dark:bg-slate-900 dark:text-emerald-300">
                  {completed ? 'Done' : module.level}
                </span>
              </div>
              <div className="mt-4 flex-1">
                <p className="text-xs font-semibold uppercase tracking-wide text-emerald-700 dark:text-emerald-300">
                  {module.level}
                </p>
                <h2 className="mt-1 text-lg font-semibold text-slate-950 dark:text-white">
                  {module.title}
                </h2>
                <p className="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-300">
                  {module.summary}
                </p>
              </div>
              <ul className="mt-4 space-y-2">
                {module.lessons.map((lesson) => (
                  <li
                    key={lesson}
                    className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300"
                  >
                    <CheckCircle2 size={16} className="shrink-0 text-emerald-500" />
                    {lesson}
                  </li>
                ))}
              </ul>
              </Panel>
            </button>
          )
        })}
        {filteredModules.length === 0 && (
          <Panel className="md:col-span-2 xl:col-span-3">
            <p className="text-sm text-slate-600 dark:text-slate-300">
              No modules match that search.
            </p>
          </Panel>
        )}
      </section>

      <section className="grid gap-4 lg:grid-cols-[0.9fr_1.1fr]">
        <Panel>
          <div className="mb-4 flex items-center gap-3">
            <span className="grid h-10 w-10 place-items-center rounded-lg bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300">
              <BookOpenCheck size={20} />
            </span>
            <div>
              <p className="text-sm font-medium text-emerald-700 dark:text-emerald-300">
                Daily checklist
              </p>
              <h2 className="text-lg font-semibold">Before you click</h2>
            </div>
          </div>
          <div className="space-y-3">
            {checklist.map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => toggleChecklistItem(item)}
                className={`flex w-full items-start gap-3 rounded-lg border p-3 text-left transition ${
                  checkedItems.includes(item)
                    ? 'border-emerald-500 bg-emerald-100 dark:bg-emerald-950/40'
                    : 'border-emerald-100 bg-emerald-50/60 hover:border-emerald-300 dark:border-slate-700 dark:bg-slate-900/60'
                }`}
              >
                <BadgeCheck
                  size={18}
                  className={`mt-0.5 shrink-0 ${
                    checkedItems.includes(item) ? 'text-emerald-600' : 'text-slate-400'
                  }`}
                />
                <p
                  className={`text-sm leading-6 ${
                    checkedItems.includes(item)
                      ? 'font-semibold text-emerald-800 dark:text-emerald-300'
                      : 'text-slate-700 dark:text-slate-300'
                  }`}
                >
                  {item}
                </p>
              </button>
            ))}
          </div>
          <p className="mt-3 text-sm font-medium text-emerald-700 dark:text-emerald-300">
            {checkedItems.length}/{checklist.length} checked
          </p>
        </Panel>

        <Panel>
          <div className="mb-4 flex items-center gap-3">
            <span className="grid h-10 w-10 place-items-center rounded-lg bg-violet-50 text-violet-700 dark:bg-violet-950/40 dark:text-violet-300">
              <Brain size={20} />
            </span>
            <div>
              <p className="text-sm font-medium text-emerald-700 dark:text-emerald-300">
                Quick practice
              </p>
              <h2 className="text-lg font-semibold">Scenario trainer</h2>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                Score: {quizScore}/{scenarios.length} correct
              </p>
            </div>
          </div>
          <div className="space-y-3">
            {scenarios.map((scenario) => (
              <div
                key={scenario.prompt}
                className="rounded-lg border border-emerald-100 p-3 dark:border-slate-700"
              >
                <p className="text-sm font-semibold text-slate-950 dark:text-white">
                  {scenario.prompt}
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {scenario.choices.map((choice) => {
                    const selected = scenarioAnswers[scenario.prompt] === choice
                    return (
                      <button
                        key={choice}
                        type="button"
                        onClick={() => chooseScenarioAnswer(scenario.prompt, choice)}
                        className={`rounded-lg border px-3 py-2 text-xs font-semibold transition ${
                          selected
                            ? choice === scenario.answer
                              ? 'border-emerald-500 bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300'
                              : 'border-rose-400 bg-rose-100 text-rose-700 dark:bg-rose-950/50 dark:text-rose-300'
                            : 'border-emerald-100 bg-white text-slate-600 hover:border-emerald-300 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300'
                        }`}
                      >
                        {choice}
                      </button>
                    )
                  })}
                </div>
                {scenarioAnswers[scenario.prompt] && (
                  <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">
                    {scenarioAnswers[scenario.prompt] === scenario.answer
                      ? 'Correct. '
                      : 'Not quite. '}
                    {scenario.reason}
                  </p>
                )}
              </div>
            ))}
          </div>
          <button
            type="button"
            onClick={() => setScenarioAnswers({})}
            className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-lg border border-emerald-200 px-4 py-3 text-sm font-semibold text-emerald-800 transition hover:bg-emerald-50 dark:border-slate-700 dark:text-emerald-300 dark:hover:bg-slate-900"
          >
            <RotateCcw size={16} />
            Reset quiz
          </button>
          {quizAnswered === scenarios.length && (
            <p className="mt-3 rounded-lg bg-emerald-50 p-3 text-sm font-medium text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300">
              {quizScore === scenarios.length
                ? 'Perfect score. You caught every threat pattern.'
                : 'Review the explanations, then try the quiz again.'}
            </p>
          )}
        </Panel>
      </section>

      {selectedModule && SelectedIcon && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/35 p-4 backdrop-blur-sm">
          <div className="max-h-[calc(100vh-2rem)] w-full max-w-3xl overflow-auto rounded-lg border border-emerald-200 bg-white/90 p-5 shadow-2xl dark:border-slate-700 dark:bg-slate-900/90">
            <div className="mb-4 flex items-start justify-between gap-3">
              <div className="flex min-w-0 gap-3">
                <span
                  className={`grid h-11 w-11 shrink-0 place-items-center rounded-lg ${selectedModule.accent}`}
                >
                  <SelectedIcon size={22} />
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-medium text-emerald-700 dark:text-emerald-300">
                    Selected module
                  </p>
                  <h2 className="mt-1 text-xl font-semibold text-slate-950 dark:text-white">
                    {selectedModule.title}
                  </h2>
                  <p className="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-300">
                    {selectedModule.summary}
                  </p>
                </div>
              </div>
              <button
                type="button"
                aria-label="Close selected module"
                onClick={() => setActiveModule('')}
                className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-emerald-100 bg-white/80 text-slate-500 transition hover:border-emerald-300 hover:text-slate-950 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:text-white"
              >
                <X size={18} />
              </button>
            </div>
            <div className="grid gap-2 sm:grid-cols-3">
              {selectedModule.lessons.map((lesson, index) => (
                <button
                  key={lesson}
                  type="button"
                  onClick={() => setActiveLessonIndex(index)}
                  className={`rounded-lg border p-3 text-left transition ${
                    activeLessonIndex === index
                      ? 'border-emerald-500 bg-emerald-100 dark:bg-emerald-950/40'
                      : 'border-emerald-100 bg-emerald-50/60 hover:border-emerald-300 dark:border-slate-700 dark:bg-slate-900/60'
                  }`}
                >
                  <p className="text-xs font-semibold uppercase tracking-wide text-emerald-700 dark:text-emerald-300">
                    Lesson {index + 1}
                  </p>
                  <p className="mt-1 text-sm font-semibold text-slate-950 dark:text-white">
                    {lesson}
                  </p>
                </button>
              ))}
            </div>
            <div className="mt-4 rounded-lg border border-emerald-100 bg-white/70 p-4 dark:border-slate-700 dark:bg-slate-900/60">
              <p className="text-xs font-semibold uppercase tracking-wide text-emerald-700 dark:text-emerald-300">
                Active lesson
              </p>
              <h3 className="mt-1 text-lg font-semibold text-slate-950 dark:text-white">
                {activeLesson}
              </h3>
              <p className="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-300">
                Review this concept, then mark the module complete when you can explain the risk and
                the safe action in your own words.
              </p>
              <div className="mt-3 flex gap-2">
                <button
                  type="button"
                  onClick={() =>
                    setActiveLessonIndex((current) =>
                      current === 0 ? selectedModule.lessons.length - 1 : current - 1,
                    )
                  }
                  className="rounded-lg border border-emerald-200 px-3 py-2 text-sm font-semibold text-emerald-800 transition hover:bg-emerald-50 dark:border-slate-700 dark:text-emerald-300"
                >
                  Previous
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setActiveLessonIndex((current) =>
                      current === selectedModule.lessons.length - 1 ? 0 : current + 1,
                    )
                  }
                  className="rounded-lg bg-emerald-600 px-3 py-2 text-sm font-semibold text-white transition hover:bg-emerald-700"
                >
                  Next lesson
                </button>
              </div>
            </div>
            <label className="mt-4 block">
              <span className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-950 dark:text-white">
                <ListChecks size={17} className="text-emerald-500" />
                My notes for this module
              </span>
              <textarea
                className="min-h-28 w-full resize-y rounded-lg border border-emerald-100 bg-white/80 px-3 py-3 text-sm outline-none transition focus:border-emerald-500 dark:border-slate-700 dark:bg-slate-900/70"
                value={moduleNotes[selectedModule.title] ?? ''}
                onChange={(event) =>
                  setModuleNotes((current) => ({
                    ...current,
                    [selectedModule.title]: event.target.value,
                  }))
                }
                placeholder="Type reminders, warning signs, or examples here"
              />
            </label>
            <button
              type="button"
              onClick={() => toggleComplete(selectedModule.title)}
              className={`mt-4 inline-flex w-full items-center justify-center gap-2 rounded-lg px-4 py-3 text-sm font-semibold transition ${
                completedModules.includes(selectedModule.title)
                  ? 'border border-emerald-200 bg-white text-emerald-700 dark:border-slate-700 dark:bg-slate-900 dark:text-emerald-300'
                  : 'bg-emerald-600 text-white hover:bg-emerald-700'
              }`}
            >
              <CheckCircle2 size={17} />
              {completedModules.includes(selectedModule.title)
                ? 'Mark as not finished'
                : 'Mark module complete'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
