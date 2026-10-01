import { Router } from 'express'
import { dbPromise, fromJson, toJson } from '../db/database.js'
import { datasetCatalog, prepareEvaluation, executeEvaluation, binaryPolicy } from '../../evaluation/workflow.mjs'
import { EvaluationError } from '../../evaluation/dataset.mjs'

// Mounted inside adminRoutes, after strict authentication and rate limiting.
export const evaluationRoutes = Router()
const mapRun = ({ report, ...row }) => ({ ...row, ...(report ? { report: fromJson(report, null) } : {}) })
let running = false

// The existing deployment runs a single Node service. Jobs run in that process;
// preserve history but mark unfinished work honestly after a service restart.
export async function recoverInterruptedEvaluations() {
  await (await dbPromise).run('UPDATE evaluation_runs SET status = ?, error = ?, completed_at = ? WHERE status = ?',
    'interrupted', 'Server restarted before evaluation completed; rerun required', new Date().toISOString(), 'running')
}

evaluationRoutes.get('/', async (_req, res, next) => {
  try {
    const db = await dbPromise
    const history = await db.all('SELECT id, dataset, mode, status, processed, total, created_at, completed_at, error FROM evaluation_runs ORDER BY created_at DESC LIMIT 50')
    res.json({ datasets: datasetCatalog(), policy: binaryPolicy, history })
  } catch (error) { next(error) }
})

evaluationRoutes.get('/:id', async (req, res, next) => {
  try {
    const row = await (await dbPromise).get('SELECT * FROM evaluation_runs WHERE id = ?', req.params.id)
    if (!row) return res.status(404).json({ error: 'Evaluation not found' })
    res.json(mapRun(row))
  } catch (error) { next(error) }
})

evaluationRoutes.post('/', async (req, res, next) => {
  if (running) return res.status(409).json({ error: 'An evaluation is already running on this server' })
  running = true
  let id
  try {
    const prepared = prepareEvaluation(req.body)
    const db = await dbPromise
    id = crypto.randomUUID()
    await db.run('INSERT INTO evaluation_runs (id, dataset, mode, status, processed, total, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      id, prepared.dataset, prepared.mode, 'running', 0, prepared.selected.length, new Date().toISOString())
    res.status(202).json({ id, status: 'running', total: prepared.selected.length })
    // Keep the request short; the admin UI polls durable progress/history.
    void (async () => {
      try {
        const report = await executeEvaluation(prepared, async (processed) => {
          await db.run('UPDATE evaluation_runs SET processed = ? WHERE id = ?', processed, id)
        })
        await db.run('UPDATE evaluation_runs SET status = ?, report = ?, completed_at = ? WHERE id = ?',
          report.failures.length ? 'completed-with-errors' : 'completed', toJson(report), new Date().toISOString(), id)
      } catch {
        await db.run('UPDATE evaluation_runs SET status = ?, error = ?, completed_at = ? WHERE id = ?', 'failed', 'Evaluation failed; no metrics fabricated', new Date().toISOString(), id)
      } finally { running = false }
    })().catch((error) => console.error('Evaluation persistence failed', error))
  } catch (error) {
    running = false
    if (error instanceof EvaluationError) return res.status(400).json({ error: error.message })
    next(error)
  }
})
